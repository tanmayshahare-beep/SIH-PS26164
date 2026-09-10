"""Config detector for Terraform, K8s, CloudFormation, nginx, Apache, Dockerfile."""

import logging
import re
from pathlib import Path

import hcl2
import yaml

from cbomscan.models import Occurrence, RawFinding

logger = logging.getLogger(__name__)

# Cloud KMS/HSM service patterns
CLOUD_KMS_PATTERNS = {
    # AWS
    "aws_kms": [
        r"aws_kms_key",
        r"aws_kms_alias",
        r"aws_kms_replica_key",
        r"aws_kms_ciphertext",
        r"aws_kms_secrets",
        r"kms\.encrypt",
        r"kms\.decrypt",
        r"kms\.generate_data_key",
        r"kms\.re_encrypt",
    ],
    "aws_acm": [
        r"aws_acm_certificate",
        r"aws_acm_certificate_validation",
        r"acm\.import_certificate",
        r"acm\.request_certificate",
    ],
    "aws_cloudhsm": [
        r"aws_cloudhsm_v2_cluster",
        r"aws_cloudhsm_v2_hsm",
        r"cloudhsm",
    ],
    # Azure
    "azure_key_vault": [
        r"azurerm_key_vault",
        r"azurerm_key_vault_key",
        r"azurerm_key_vault_secret",
        r"azurerm_key_vault_certificate",
        r"keyvault\.vaults",
        r"Microsoft\.KeyVault",
    ],
    # GCP
    "gcp_kms": [
        r"google_kms_crypto_key",
        r"google_kms_key_ring",
        r"google_kms_key_ring_iam",
        r"kms\.v1\.KeyManagementService",
        r"cloudkms",
    ],
    # Generic KMS references
    "generic_kms": [
        r"kms[_-]?key",
        r"key[_-]?management[_-]?service",
        r"hardware[_-]?security[_-]?module",
        r"hsm",
    ],
}

# TLS/SSL protocol patterns for nginx/Apache
TLS_PATTERNS = {
    "nginx": {
        "ssl_protocols": r"ssl_protocols\s+([^;]+)",
        "ssl_ciphers": r"ssl_ciphers\s+([^;]+)",
        "ssl_prefer_server_ciphers": r"ssl_prefer_server_ciphers\s+(on|off)",
        "ssl_session_cache": r"ssl_session_cache\s+([^;]+)",
        "ssl_session_timeout": r"ssl_session_timeout\s+([^;]+)",
    },
    "apache": {
        "ssl_protocol": r"SSLProtocol\s+([^\n]+)",
        "ssl_cipher_suite": r"SSLCipherSuite\s+([^\n]+)",
        "ssl_honor_cipher_order": r"SSLHonorCipherOrder\s+(on|off)",
        "ssl_session_cache": r"SSLSessionCache\s+([^\n]+)",
    },
}

# Weak TLS versions/ciphers to flag
WEAK_TLS_VERSIONS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]
WEAK_CIPHER_PATTERNS = [
    r"RC4",
    r"DES",
    r"3DES",
    r"MD5",
    r"SHA1",
    r"NULL",
    r"EXPORT",
    r"ANON",
    r"CBC",
]


def _detect_terraform_kms(content: str, file_path: str) -> list[RawFinding]:
    """Detect cloud KMS references in Terraform HCL."""
    findings = []
    try:
        parsed = hcl2.loads(content)
    except Exception:
        logger.debug("Could not parse %s", file_path, exc_info=True)
        return findings

    def _visit(obj, path=""):
        if isinstance(obj, dict):
            for key, value in obj.items():
                new_path = f"{path}.{key}" if path else key
                # Check resource types
                if key == "resource" and isinstance(value, list):
                    for resource_block in value:
                        if isinstance(resource_block, dict):
                            for resource_type in resource_block:
                                for kms_type, patterns in CLOUD_KMS_PATTERNS.items():
                                    for pattern in patterns:
                                        if re.search(pattern, resource_type, re.IGNORECASE):
                                            finding = _create_kms_finding(
                                                kms_type, resource_type, file_path, new_path
                                            )
                                            findings.append(finding)
                _visit(value, new_path)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                _visit(item, f"{path}[{i}]")

    _visit(parsed)
    return findings


def _detect_k8s_kms(content: str, file_path: str) -> list[RawFinding]:
    """Detect cloud KMS references in K8s YAML."""
    findings = []
    try:
        docs = list(yaml.safe_load_all(content))
    except Exception:
        logger.debug("Could not parse %s", file_path, exc_info=True)
        return findings

    for doc in docs:
        if not isinstance(doc, dict):
            continue
        # Check for KMS-related kinds
        kind = doc.get("kind", "")
        if any(
            kms_kind in kind.lower() for kms_kind in ["kms", "keyvault", "secret", "certificate"]
        ):
            # Look for provider-specific annotations or spec fields
            spec = doc.get("spec", {})
            metadata = doc.get("metadata", {})
            annotations = metadata.get("annotations", {})

            for kms_type, patterns in CLOUD_KMS_PATTERNS.items():
                for pattern in patterns:
                    # Check kind, spec, and annotations
                    for check_str in [kind, str(spec), str(annotations)]:
                        if re.search(pattern, check_str, re.IGNORECASE):
                            finding = _create_kms_finding(kms_type, kind, file_path, f"kind={kind}")
                            findings.append(finding)
    return findings


def _detect_cloudformation_kms(content: str, file_path: str) -> list[RawFinding]:
    """Detect cloud KMS references in CloudFormation YAML/JSON."""
    findings = []
    try:
        if content.strip().startswith("{"):
            import json

            template = json.loads(content)
        else:
            template = yaml.safe_load(content)
    except Exception:
        logger.debug("Could not parse %s", file_path, exc_info=True)
        return findings

    resources = template.get("Resources", {})
    for resource_name, resource_def in resources.items():
        if not isinstance(resource_def, dict):
            continue
        resource_type = resource_def.get("Type", "")
        for kms_type, patterns in CLOUD_KMS_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, resource_type, re.IGNORECASE):
                    finding = _create_kms_finding(
                        kms_type, resource_type, file_path, f"Resource:{resource_name}"
                    )
                    findings.append(finding)
    return findings


def _create_kms_finding(kms_type: str, matched: str, file_path: str, location: str):
    """Create a flagged finding for KMS reference."""
    kms_names = {
        "aws_kms": "AWS KMS",
        "aws_acm": "AWS ACM",
        "aws_cloudhsm": "AWS CloudHSM",
        "azure_key_vault": "Azure Key Vault",
        "gcp_kms": "GCP KMS",
        "generic_kms": "Generic KMS/HSM",
    }
    name = kms_names.get(kms_type, kms_type)

    occurrence = Occurrence(
        file=file_path,
        line=None,
        symbol=location,
    )

    return RawFinding(
        asset_type="protocol",
        name=f"Cloud KMS: {name}",
        occurrences=[occurrence],
        primitive="key-management",
        confidence="flagged",
        metadata={
            "matched_pattern": matched,
            "note": (
                f"{name} reference detected - algorithm not statically "
                "determinable, manual review required"
            ),
        },
    )


def _detect_nginx_tls(content: str, file_path: str) -> list[RawFinding]:
    """Detect TLS configuration in nginx config."""
    findings = []
    lines = content.split("\n")

    for line_num, line in enumerate(lines, 1):
        line_stripped = line.strip()
        if line_stripped.startswith("#"):
            continue

        for pattern_name, pattern in TLS_PATTERNS["nginx"].items():
            match = re.search(pattern, line_stripped)
            if match:
                value = match.group(1).strip()
                finding = _create_tls_finding(
                    "nginx", pattern_name, value, file_path, line_num, line_stripped
                )
                findings.append(finding)

    return findings


def _detect_apache_tls(content: str, file_path: str) -> list[RawFinding]:
    """Detect TLS configuration in Apache config."""
    findings = []
    lines = content.split("\n")

    for line_num, line in enumerate(lines, 1):
        line_stripped = line.strip()
        if line_stripped.startswith("#"):
            continue

        for pattern_name, pattern in TLS_PATTERNS["apache"].items():
            match = re.search(pattern, line_stripped, re.IGNORECASE)
            if match:
                value = match.group(1).strip()
                finding = _create_tls_finding(
                    "apache", pattern_name, value, file_path, line_num, line_stripped
                )
                findings.append(finding)

    return findings


def _create_tls_finding(
    server_type: str, pattern_name: str, value: str, file_path: str, line_num: int, raw_line: str
):
    """Create a flagged finding for TLS config."""
    # Check for weak configurations
    is_weak = False
    weakness_notes = []

    if "protocol" in pattern_name:
        for weak_version in WEAK_TLS_VERSIONS:
            if weak_version in value:
                is_weak = True
                weakness_notes.append(f"Uses deprecated {weak_version}")

    if "cipher" in pattern_name:
        for weak_pattern in WEAK_CIPHER_PATTERNS:
            if re.search(weak_pattern, value, re.IGNORECASE):
                is_weak = True
                weakness_notes.append(f"Uses weak cipher pattern: {weak_pattern}")

    asset_type = "protocol"
    name = f"TLS Config: {server_type} {pattern_name}"
    if is_weak:
        name += " (WEAK)"

    occurrence = Occurrence(
        file=file_path,
        line=line_num,
        symbol=pattern_name,
    )

    note = f"{server_type} {pattern_name}: {value}"
    if weakness_notes:
        note += " | " + "; ".join(weakness_notes)
    note += " — manual review required for quantum readiness"

    return RawFinding(
        asset_type=asset_type,
        name=name,
        occurrences=[occurrence],
        primitive="tls-config",
        confidence="flagged",
        metadata={
            "server_type": server_type,
            "config_directive": pattern_name,
            "value": value,
            "raw_line": raw_line,
            "is_weak": is_weak,
            "weakness_notes": weakness_notes,
            "note": note,
        },
    )


def _detect_dockerfile_base_image(content: str, file_path: str):
    """Detect FROM base images in Dockerfile."""
    findings = []
    lines = content.split("\n")

    for line_num, line in enumerate(lines, 1):
        line_stripped = line.strip()
        if line_stripped.startswith("#"):
            continue

        # Match FROM instructions
        match = re.match(r"FROM\s+([^\s]+)(?:\s+AS\s+\w+)?", line_stripped, re.IGNORECASE)
        if match:
            image = match.group(1)
            occurrence = Occurrence(
                file=file_path,
                line=line_num,
                symbol="FROM",
            )

            finding = RawFinding(
                asset_type="related-crypto-material",
                name=f"Container Base Image: {image}",
                occurrences=[occurrence],
                primitive="container-image",
                confidence="flagged",
                metadata={
                    "image": image,
                    "note": (
                        f"Base image {image} may contain cryptographic libraries "
                        "- out of static analysis scope, manual review required"
                    ),
                },
            )
            findings.append(finding)

    return findings


class ConfigDetector:
    """Detector for config files: Terraform, K8s, CloudFormation, nginx, Apache, Dockerfile."""

    name = "config"
    title = "Config & Infrastructure Detector"
    summary = (
        "Catalogues crypto references in infrastructure config that cannot be "
        "resolved statically."
    )
    detail = (
        "Scans Terraform, Kubernetes, CloudFormation, nginx/Apache and Dockerfiles for "
        "references to managed key material and TLS settings. The concrete algorithm "
        "lives in the cloud service or base image, not the repository, so every finding "
        "is marked 'flagged' for manual review rather than given a verdict."
    )
    typical_confidence = "flagged"
    inputs = [".tf", ".tfvars", ".yaml", ".yml", ".conf", "Dockerfile"]
    detects = [
        "Cloud KMS/HSM references (AWS KMS/ACM/CloudHSM, Azure Key Vault, GCP KMS)",
        "TLS protocol and cipher-suite configuration, including weak selections",
        "Container base images that may ship their own crypto libraries",
    ]
    supported_extensions = [".tf", ".tfvars", ".yaml", ".yml", ".conf", ".config", "Dockerfile"]

    def detect(self, file_path: str, content: str) -> list[RawFinding]:
        findings = []
        file_name = Path(file_path).name
        file_ext = Path(file_path).suffix.lower()

        # Terraform
        if file_ext in (".tf", ".tfvars"):
            findings.extend(_detect_terraform_kms(content, file_path))

        # K8s / CloudFormation (YAML)
        elif file_ext in (".yaml", ".yml"):
            # Check if it's K8s or CloudFormation by content
            if self._is_k8s(content):
                findings.extend(_detect_k8s_kms(content, file_path))
            elif self._is_cloudformation(content):
                findings.extend(_detect_cloudformation_kms(content, file_path))

        # nginx config
        elif "nginx" in file_name.lower() or file_ext == ".conf":
            findings.extend(_detect_nginx_tls(content, file_path))

        # Apache config
        elif "httpd" in file_name.lower() or "apache" in file_name.lower():
            findings.extend(_detect_apache_tls(content, file_path))

        # Dockerfile
        elif file_name == "Dockerfile" or file_name.startswith("Dockerfile."):
            findings.extend(_detect_dockerfile_base_image(content, file_path))

        return findings

    def _is_k8s(self, content: str) -> bool:
        """Heuristic to detect K8s YAML."""
        k8s_indicators = [
            "apiVersion:",
            "kind:",
            "metadata:",
            "spec:",
            "Deployment",
            "Service",
            "ConfigMap",
            "Secret",
            "Ingress",
        ]
        return any(indicator in content for indicator in k8s_indicators)

    def _is_cloudformation(self, content: str) -> bool:
        """Heuristic to detect CloudFormation template."""
        cf_indicators = [
            "AWSTemplateFormatVersion",
            "Resources:",
            "Parameters:",
            "Outputs:",
            "Transform:",
        ]
        return any(indicator in content for indicator in cf_indicators)
