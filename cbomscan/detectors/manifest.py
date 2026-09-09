"""Manifest detector for Python and JavaScript/TypeScript dependency files."""

import json
import re
import tomllib
from pathlib import Path

from cbomscan.models import Occurrence

# Map of known crypto libraries to the algorithm families they imply
# Python libraries
CRYPTO_LIBRARY_MAP: dict[str, list[dict]] = {
    "cryptography": [
        {"name": "RSA", "primitive": "pke", "key_size": 2048},
        {"name": "ECDSA", "primitive": "signature"},
        {"name": "ECDH", "primitive": "key-agree"},
        {"name": "Ed25519", "primitive": "signature"},
        {"name": "X25519", "primitive": "key-agree"},
        {"name": "AES-256", "primitive": "block-cipher", "key_size": 256},
        {"name": "AES-128", "primitive": "block-cipher", "key_size": 128},
        {"name": "ChaCha20", "primitive": "stream-cipher", "key_size": 256},
        {"name": "SHA-256", "primitive": "hash"},
        {"name": "SHA-384", "primitive": "hash"},
        {"name": "SHA-512", "primitive": "hash"},
        {"name": "HMAC", "primitive": "mac"},
        {"name": "HKDF", "primitive": "kdf"},
        {"name": "PBKDF2", "primitive": "kdf"},
    ],
    "pycryptodome": [
        {"name": "RSA", "primitive": "pke"},
        {"name": "DSA", "primitive": "signature"},
        {"name": "ECDSA", "primitive": "signature"},
        {"name": "AES-256", "primitive": "block-cipher", "key_size": 256},
        {"name": "AES-128", "primitive": "block-cipher", "key_size": 128},
        {"name": "3DES", "primitive": "block-cipher", "key_size": 168},
        {"name": "DES", "primitive": "block-cipher", "key_size": 56},
        {"name": "ChaCha20", "primitive": "stream-cipher", "key_size": 256},
        {"name": "SHA-256", "primitive": "hash"},
        {"name": "SHA-1", "primitive": "hash"},
        {"name": "MD5", "primitive": "hash"},
        {"name": "HMAC", "primitive": "mac"},
    ],
    "rsa": [
        {"name": "RSA", "primitive": "pke", "key_size": 2048},
    ],
    "ecdsa": [
        {"name": "ECDSA", "primitive": "signature"},
        {"name": "ECDH", "primitive": "key-agree"},
    ],
    "pyopenssl": [
        {"name": "RSA", "primitive": "pke"},
        {"name": "ECDSA", "primitive": "signature"},
        {"name": "ECDH", "primitive": "key-agree"},
        {"name": "AES-256", "primitive": "block-cipher", "key_size": 256},
        {"name": "AES-128", "primitive": "block-cipher", "key_size": 128},
        {"name": "3DES", "primitive": "block-cipher", "key_size": 168},
        {"name": "SHA-256", "primitive": "hash"},
        {"name": "SHA-1", "primitive": "hash"},
    ],
    "pynacl": [
        {"name": "Ed25519", "primitive": "signature"},
        {"name": "X25519", "primitive": "key-agree"},
        {"name": "ChaCha20", "primitive": "stream-cipher", "key_size": 256},
        {"name": "Salsa20", "primitive": "stream-cipher", "key_size": 256},
        {"name": "Blake2b", "primitive": "hash"},
    ],
    "paramiko": [
        {"name": "RSA", "primitive": "pke"},
        {"name": "ECDSA", "primitive": "signature"},
        {"name": "ECDH", "primitive": "key-agree"},
        {"name": "Ed25519", "primitive": "signature"},
        {"name": "AES-256", "primitive": "block-cipher", "key_size": 256},
        {"name": "AES-128", "primitive": "block-cipher", "key_size": 128},
        {"name": "3DES", "primitive": "block-cipher", "key_size": 168},
        {"name": "SHA-256", "primitive": "hash"},
        {"name": "SHA-1", "primitive": "hash"},
    ],
}

# JavaScript/TypeScript crypto libraries mapping
JS_CRYPTO_LIBRARY_MAP: dict[str, list[dict]] = {
    "node-forge": [
        {"name": "RSA", "primitive": "pke", "key_size": 2048},
        {"name": "ECDSA", "primitive": "signature"},
        {"name": "AES-256", "primitive": "block-cipher", "key_size": 256},
        {"name": "AES-128", "primitive": "block-cipher", "key_size": 128},
        {"name": "3DES", "primitive": "block-cipher", "key_size": 168},
        {"name": "SHA-256", "primitive": "hash"},
        {"name": "SHA-1", "primitive": "hash"},
        {"name": "MD5", "primitive": "hash"},
        {"name": "HMAC", "primitive": "mac"},
        {"name": "PBKDF2", "primitive": "kdf"},
    ],
    "elliptic": [
        {"name": "ECDSA", "primitive": "signature"},
        {"name": "ECDH", "primitive": "key-agree"},
        {"name": "Ed25519", "primitive": "signature"},
    ],
    "node-rsa": [
        {"name": "RSA", "primitive": "pke", "key_size": 2048},
    ],
    "tweetnacl": [
        {"name": "Ed25519", "primitive": "signature"},
        {"name": "X25519", "primitive": "key-agree"},
        {"name": "ChaCha20", "primitive": "stream-cipher", "key_size": 256},
        {"name": "Salsa20", "primitive": "stream-cipher", "key_size": 256},
        {"name": "Blake2b", "primitive": "hash"},
    ],
    "jsonwebtoken": [
        {"name": "RSA", "primitive": "signature"},
        {"name": "ECDSA", "primitive": "signature"},
        {"name": "HMAC", "primitive": "mac"},
    ],
    "jose": [
        {"name": "RSA", "primitive": "signature"},
        {"name": "ECDSA", "primitive": "signature"},
        {"name": "ECDH", "primitive": "key-agree"},
        {"name": "Ed25519", "primitive": "signature"},
        {"name": "AES-256", "primitive": "block-cipher", "key_size": 256},
        {"name": "HMAC", "primitive": "mac"},
        {"name": "PBKDF2", "primitive": "kdf"},
    ],
    "webcrypto": [
        {"name": "RSA", "primitive": "pke"},
        {"name": "ECDSA", "primitive": "signature"},
        {"name": "ECDH", "primitive": "key-agree"},
        {"name": "AES-256", "primitive": "block-cipher", "key_size": 256},
        {"name": "HMAC", "primitive": "mac"},
        {"name": "HKDF", "primitive": "kdf"},
        {"name": "PBKDF2", "primitive": "kdf"},
    ],
    "crypto": [
        # Node.js built-in crypto module - this is a special case
        # Since it's built-in, it won't appear in package.json
        # But we keep it here for reference
        {"name": "RSA", "primitive": "pke"},
        {"name": "ECDSA", "primitive": "signature"},
        {"name": "ECDH", "primitive": "key-agree"},
        {"name": "Ed25519", "primitive": "signature"},
        {"name": "X25519", "primitive": "key-agree"},
        {"name": "DH", "primitive": "key-agree"},
        {"name": "AES-256", "primitive": "block-cipher", "key_size": 256},
        {"name": "AES-128", "primitive": "block-cipher", "key_size": 128},
        {"name": "3DES", "primitive": "block-cipher", "key_size": 168},
        {"name": "ChaCha20", "primitive": "stream-cipher", "key_size": 256},
        {"name": "SHA-256", "primitive": "hash"},
        {"name": "SHA-384", "primitive": "hash"},
        {"name": "SHA-512", "primitive": "hash"},
        {"name": "SHA-1", "primitive": "hash"},
        {"name": "MD5", "primitive": "hash"},
        {"name": "HMAC", "primitive": "mac"},
        {"name": "PBKDF2", "primitive": "kdf"},
        {"name": "Scrypt", "primitive": "kdf"},
        {"name": "HKDF", "primitive": "kdf"},
    ],
    "@noble/hashes": [
        {"name": "SHA-256", "primitive": "hash"},
        {"name": "SHA-384", "primitive": "hash"},
        {"name": "SHA-512", "primitive": "hash"},
        {"name": "SHA-1", "primitive": "hash"},
        {"name": "MD5", "primitive": "hash"},
        {"name": "Blake2b", "primitive": "hash"},
        {"name": "Blake2s", "primitive": "hash"},
        {"name": "RIPEMD160", "primitive": "hash"},
    ],
    "@noble/secp256k1": [
        {"name": "ECDSA", "primitive": "signature"},
        {"name": "ECDH", "primitive": "key-agree"},
    ],
    "@noble/ed25519": [
        {"name": "Ed25519", "primitive": "signature"},
    ],
    "@noble/curves": [
        {"name": "ECDSA", "primitive": "signature"},
        {"name": "ECDH", "primitive": "key-agree"},
        {"name": "Ed25519", "primitive": "signature"},
        {"name": "X25519", "primitive": "key-agree"},
    ],
}


def _parse_requirements_txt(content: str) -> list[str]:
    """Parse requirements.txt and return list of package names."""
    packages = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Remove version specifiers and extras
        pkg = re.split(r"[=<>!~\[@]", line)[0].strip()
        if pkg:
            packages.append(pkg.lower())
    return packages


def _parse_pyproject_toml(content: str) -> list[str]:
    """Parse pyproject.toml and return list of package names from dependencies."""
    packages = []
    try:
        data = tomllib.loads(content)
        # Check project.dependencies
        deps = data.get("project", {}).get("dependencies", [])
        for dep in deps:
            pkg = re.split(r"[=<>!~\[@]", dep)[0].strip().lower()
            if pkg:
                packages.append(pkg)
        # Check tool.poetry.dependencies
        poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
        for pkg in poetry_deps:
            if pkg.lower() != "python":
                packages.append(pkg.lower())
        # Check tool.pdm.dependencies
        pdm_deps = data.get("tool", {}).get("pdm", {}).get("dependencies", {})
        for pkg in pdm_deps:
            if pkg.lower() != "python":
                packages.append(pkg.lower())
    except Exception:
        pass
    return packages


def _parse_package_json(content: str) -> list[str]:
    """Parse package.json and return list of package names from dependencies."""
    packages = []
    try:
        data = json.loads(content)
        # Check dependencies
        deps = data.get("dependencies", {})
        for pkg in deps:
            packages.append(pkg.lower())
        # Check devDependencies
        dev_deps = data.get("devDependencies", {})
        for pkg in dev_deps:
            packages.append(pkg.lower())
        # Check peerDependencies
        peer_deps = data.get("peerDependencies", {})
        for pkg in peer_deps:
            packages.append(pkg.lower())
        # Check optionalDependencies
        opt_deps = data.get("optionalDependencies", {})
        for pkg in opt_deps:
            packages.append(pkg.lower())
    except Exception:
        pass
    return packages


class ManifestDetector:
    """Detector for Python and JavaScript/TypeScript manifest files."""

    name = "manifest"
    supported_extensions = [".txt", ".toml", ".json"]

    def detect(self, file_path: str, content: str):
        # Import here to avoid circular import
        from cbomscan.detectors import RawFinding

        findings = []
        file_name = Path(file_path).name

        if file_name == "requirements.txt":
            packages = _parse_requirements_txt(content)
            library_map = CRYPTO_LIBRARY_MAP
        elif file_name in ("pyproject.toml",):
            packages = _parse_pyproject_toml(content)
            library_map = CRYPTO_LIBRARY_MAP
        elif file_name == "package.json":
            packages = _parse_package_json(content)
            library_map = JS_CRYPTO_LIBRARY_MAP
        else:
            return findings

        occurrence = Occurrence(file=file_path, line=None, symbol=None)

        for pkg in packages:
            if pkg in library_map:
                for algo_info in library_map[pkg]:
                    findings.append(
                        RawFinding(
                            asset_type="algorithm",
                            name=algo_info["name"],
                            occurrences=[occurrence],
                            primitive=algo_info.get("primitive"),
                            key_size=algo_info.get("key_size"),
                            confidence="inferred",
                        )
                    )

        return findings