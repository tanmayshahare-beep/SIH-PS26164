"""Certificate detector for X.509 certificates using cryptography library."""

import contextlib

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, x25519

from cbomscan.models import Occurrence, RawFinding

# Map of signature algorithm OIDs to algorithm names
SIG_ALGORITHM_MAP = {
    "1.2.840.113549.1.1.1": "RSA",
    "1.2.840.113549.1.1.4": "MD5WithRSA",
    "1.2.840.113549.1.1.5": "SHA1WithRSA",
    "1.2.840.113549.1.1.11": "SHA256WithRSA",
    "1.2.840.113549.1.1.12": "SHA384WithRSA",
    "1.2.840.113549.1.1.13": "SHA512WithRSA",
    "1.2.840.10045.4.1": "ECDSAWithSHA1",
    "1.2.840.10045.4.3.1": "ECDSAWithSHA224",
    "1.2.840.10045.4.3.2": "ECDSAWithSHA256",
    "1.2.840.10045.4.3.3": "ECDSAWithSHA384",
    "1.2.840.10045.4.3.4": "ECDSAWithSHA512",
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
}


def _get_curve_name(curve: ec.EllipticCurve) -> str | None:
    """Map cryptography curve object to curve name."""
    return getattr(curve, "name", None)


def _get_key_info(public_key) -> dict:
    """Extract key type, size, and curve from a public key."""
    info = {}

    if isinstance(public_key, rsa.RSAPublicKey):
        info["name"] = "RSA"
        info["primitive"] = "pke"
        info["key_size"] = public_key.key_size
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        info["name"] = "ECDSA"
        info["primitive"] = "signature"
        info["key_size"] = public_key.curve.key_size
        info["curve"] = _get_curve_name(public_key.curve)
    elif isinstance(public_key, ed25519.Ed25519PublicKey):
        info["name"] = "Ed25519"
        info["primitive"] = "signature"
        info["key_size"] = 256
    elif isinstance(public_key, x25519.X25519PublicKey):
        info["name"] = "X25519"
        info["primitive"] = "key-agree"
        info["key_size"] = 256
    else:
        info["name"] = type(public_key).__name__
        info["primitive"] = "unknown"

    return info


def _get_signature_algorithm(cert: x509.Certificate) -> str | None:
    """Get the signature algorithm name from certificate."""
    oid = cert.signature_algorithm_oid.dotted_string
    return SIG_ALGORITHM_MAP.get(oid, oid)


def _parse_pem(content: bytes) -> list[x509.Certificate]:
    """Parse PEM format certificates."""
    certs = []
    try:
        cert = x509.load_pem_x509_certificate(content)
        certs.append(cert)
    except ValueError:
        # Fall back to a bundle of concatenated PEM certificates.
        with contextlib.suppress(ValueError):
            certs = x509.load_pem_x509_certificates(content)
    return certs


def _parse_der(content: bytes) -> list[x509.Certificate]:
    """Parse DER format certificates."""
    certs = []
    try:
        cert = x509.load_der_x509_certificate(content)
        certs.append(cert)
    except ValueError:
        pass
    return certs


class CertDetector:
    """Detector for X.509 certificate files."""

    name = "certificate"
    title = "Certificate Detector"
    summary = "Parses X.509 certificates and reads their real signature and key parameters."
    detail = (
        "Loads PEM and DER certificates (including concatenated bundles) and extracts "
        "the signature algorithm OID, public key type, key size and curve directly "
        "from the certificate, so findings are exact rather than inferred."
    )
    typical_confidence = "confirmed"
    inputs = [".pem", ".crt", ".cer", ".der"]
    detects = [
        "Signature algorithms (sha256WithRSA, ECDSA-with-SHA*, Ed25519, ...)",
        "Public key algorithm, key size and named curve",
        "Subject, issuer, serial number and validity window",
    ]
    supported_extensions = [".pem", ".crt", ".cer", ".der"]

    def detect(self, file_path: str, content: str) -> list:
        """Detect cryptographic artifacts in a certificate file."""

        findings = []
        file_bytes = content.encode("latin-1", errors="replace")

        # Try to parse as PEM first, then DER
        certs = _parse_pem(file_bytes)
        if not certs:
            certs = _parse_der(file_bytes)

        for cert in certs:
            # Get signature algorithm
            sig_alg = _get_signature_algorithm(cert)
            if not sig_alg:
                sig_alg = cert.signature_algorithm_oid.dotted_string

            # Get public key info
            public_key = cert.public_key()
            key_info = _get_key_info(public_key)

            # Create artifact for the certificate itself
            occurrence = Occurrence(
                file=file_path,
                line=None,
                symbol=f"Certificate: {cert.subject.rfc4514_string()}",
            )

            # Create main certificate artifact
            findings.append(
                RawFinding(
                    asset_type="certificate",
                    name=sig_alg,
                    occurrences=[occurrence],
                    primitive=key_info.get("primitive"),
                    key_size=key_info.get("key_size"),
                    curve=key_info.get("curve"),
                    confidence="confirmed",
                    metadata={
                        "subject": cert.subject.rfc4514_string(),
                        "issuer": cert.issuer.rfc4514_string(),
                        "serial_number": str(cert.serial_number),
                        "not_valid_before": (
                            cert.not_valid_before_utc.isoformat()
                            if cert.not_valid_before_utc
                            else None
                        ),
                        "not_valid_after": (
                            cert.not_valid_after_utc.isoformat()
                            if cert.not_valid_after_utc
                            else None
                        ),
                        "public_key_algorithm": key_info.get("name"),
                        "public_key_size": key_info.get("key_size"),
                        "public_key_curve": key_info.get("curve"),
                    },
                )
            )

            # Also create algorithm artifact for the signature algorithm
            if sig_alg and sig_alg != key_info.get("name"):
                findings.append(
                    RawFinding(
                        asset_type="algorithm",
                        name=sig_alg,
                        occurrences=[occurrence],
                        primitive=key_info.get("primitive"),
                        key_size=key_info.get("key_size"),
                        curve=key_info.get("curve"),
                        confidence="confirmed",
                    )
                )

        return findings
