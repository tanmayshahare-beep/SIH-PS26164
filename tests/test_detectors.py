"""Tests for SourceDetector and CertDetector."""

from pathlib import Path

import pytest

from cbomscan.detectors import registry
from cbomscan.detectors.cert import CertDetector
from cbomscan.detectors.source import PythonSourceDetector, JavaScriptSourceDetector


class TestPythonSourceDetector:
    """Tests for PythonSourceDetector."""

    def test_detector_registered(self):
        """Test that PythonSourceDetector is registered."""
        detector = registry.get("python_source")
        assert detector is not None
        assert isinstance(detector, PythonSourceDetector)

    def test_supported_extensions(self):
        """Test supported extensions."""
        detector = PythonSourceDetector()
        assert ".py" in detector.supported_extensions

    def test_detect_hashlib_md5(self):
        """Test detection of hashlib.md5()."""
        detector = PythonSourceDetector()
        content = """import hashlib

def hash_data(data):
    return hashlib.md5(data).hexdigest()
"""
        findings = detector.detect("test.py", content)
        md5_findings = [f for f in findings if f.name == "MD5"]
        assert len(md5_findings) == 1
        assert md5_findings[0].confidence == "confirmed"
        assert md5_findings[0].occurrences[0].line == 4
        assert md5_findings[0].occurrences[0].symbol == "hashlib.md5"
        assert md5_findings[0].primitive == "hash"

    def test_detect_hashlib_sha1(self):
        """Test detection of hashlib.sha1()."""
        detector = PythonSourceDetector()
        content = """
import hashlib
hashlib.sha1(b"test")
"""
        findings = detector.detect("test.py", content)
        sha1_findings = [f for f in findings if f.name == "SHA-1"]
        assert len(sha1_findings) == 1
        assert sha1_findings[0].primitive == "hash"

    def test_detect_hashlib_sha256(self):
        """Test detection of hashlib.sha256()."""
        detector = PythonSourceDetector()
        content = """
import hashlib
hashlib.sha256(b"test")
"""
        findings = detector.detect("test.py", content)
        sha256_findings = [f for f in findings if f.name == "SHA-256"]
        assert len(sha256_findings) == 1
        assert sha256_findings[0].primitive == "hash"

    def test_detect_rsa_generate_private_key(self):
        """Test detection of RSA key generation."""
        detector = PythonSourceDetector()
        content = """
from cryptography.hazmat.primitives.asymmetric import rsa

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
"""
        findings = detector.detect("test.py", content)
        rsa_findings = [f for f in findings if f.name == "RSA"]
        assert len(rsa_findings) >= 1
        assert rsa_findings[0].confidence == "confirmed"
        assert rsa_findings[0].primitive == "pke"
        assert rsa_findings[0].key_size == 2048

    def test_detect_ec_generate_private_key(self):
        """Test detection of EC key generation."""
        detector = PythonSourceDetector()
        content = """
from cryptography.hazmat.primitives.asymmetric import ec

private_key = ec.generate_private_key(ec.SECP256R1())
"""
        findings = detector.detect("test.py", content)
        ec_findings = [f for f in findings if f.name in ("ECDSA", "ECDH")]
        assert len(ec_findings) >= 1

    def test_detect_ed25519(self):
        """Test detection of Ed25519."""
        detector = PythonSourceDetector()
        content = """
from cryptography.hazmat.primitives.asymmetric import ed25519

private_key = ed25519.Ed25519PrivateKey.generate()
"""
        findings = detector.detect("test.py", content)
        ed_findings = [f for f in findings if f.name == "Ed25519"]
        assert len(ed_findings) >= 1
        assert ed_findings[0].primitive == "signature"

    def test_detect_pbkdf2(self):
        """Test detection of PBKDF2."""
        detector = PythonSourceDetector()
        content = """
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from cryptography.hazmat.primitives import hashes

kdf = PBKDF2(algorithm=hashes.SHA256(), length=32, salt=b"salt", iterations=100000)
"""
        findings = detector.detect("test.py", content)
        pbkdf2_findings = [f for f in findings if f.name == "PBKDF2"]
        assert len(pbkdf2_findings) >= 1
        assert pbkdf2_findings[0].primitive == "kdf"

    def test_detect_aes_cipher(self):
        """Test detection of AES cipher."""
        detector = PythonSourceDetector()
        content = """
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

cipher = Cipher(algorithms.AES(b"0123456789abcdef0123456789abcdef"), modes.CBC(b"0123456789abcdef"))
"""
        findings = detector.detect("test.py", content)
        aes_findings = [f for f in findings if f.name == "AES-256"]
        assert len(aes_findings) >= 1
        assert aes_findings[0].primitive == "block-cipher"
        assert aes_findings[0].key_size == 256

    def test_detect_import_alias(self):
        """Test detection with import aliases."""
        detector = PythonSourceDetector()
        content = """
import hashlib as h

def hash_data(data):
    return h.md5(data).hexdigest()
"""
        findings = detector.detect("test.py", content)
        md5_findings = [f for f in findings if f.name == "MD5"]
        assert len(md5_findings) == 1
        assert md5_findings[0].confidence == "confirmed"


class TestCertDetector:
    """Tests for CertDetector."""

    def test_detector_registered(self):
        """Test that CertDetector is registered."""
        detector = registry.get("certificate")
        assert detector is not None
        assert isinstance(detector, CertDetector)

    def test_supported_extensions(self):
        """Test supported extensions."""
        detector = CertDetector()
        assert ".pem" in detector.supported_extensions
        assert ".crt" in detector.supported_extensions
        assert ".cer" in detector.supported_extensions
        assert ".der" in detector.supported_extensions

    def test_detect_self_signed_cert(self):
        """Test detection of self-signed certificate."""
        detector = CertDetector()
        cert_path = Path(__file__).parent.parent / "fixtures" / "py-sample" / "test_cert.pem"
        assert cert_path.exists()

        content = cert_path.read_text()
        findings = detector.detect(str(cert_path), content)

        # Should find at least one certificate artifact
        cert_findings = [f for f in findings if f.asset_type == "certificate"]
        assert len(cert_findings) >= 1

        cert_finding = cert_findings[0]
        assert cert_finding.confidence == "confirmed"
        assert cert_finding.asset_type == "certificate"
        assert "subject" in cert_finding.metadata
        assert "issuer" in cert_finding.metadata
        assert "not_valid_before" in cert_finding.metadata
        assert "not_valid_after" in cert_finding.metadata

    def test_cert_has_signature_algorithm(self):
        """Test that certificate has signature algorithm."""
        detector = CertDetector()
        cert_path = Path(__file__).parent.parent / "fixtures" / "py-sample" / "test_cert.pem"
        content = cert_path.read_text()
        findings = detector.detect(str(cert_path), content)

        cert_findings = [f for f in findings if f.asset_type == "certificate"]
        assert len(cert_findings) >= 1

        # The signature algorithm should be SHA256WithRSA or similar
        cert_finding = cert_findings[0]
        assert cert_finding.name in ("SHA256WithRSA", "SHA-256", "RSA")


class TestJavaScriptSourceDetector:
    """Tests for JavaScriptSourceDetector."""

    def test_detector_registered(self):
        """Test that JavaScriptSourceDetector is registered."""
        detector = registry.get("javascript_source")
        assert detector is not None
        assert isinstance(detector, JavaScriptSourceDetector)

    def test_supported_extensions(self):
        """Test supported extensions."""
        detector = JavaScriptSourceDetector()
        assert ".js" in detector.supported_extensions
        assert ".ts" in detector.supported_extensions
        assert ".jsx" in detector.supported_extensions
        assert ".tsx" in detector.supported_extensions

    def test_detect_node_crypto_generate_rsa(self):
        """Test detection of Node.js crypto.generateKeyPair for RSA."""
        detector = JavaScriptSourceDetector()
        content = """
const crypto = require('crypto');
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
});
"""
        findings = detector.detect("test.js", content)
        rsa_findings = [f for f in findings if f.name == "RSA"]
        assert len(rsa_findings) >= 1
        assert rsa_findings[0].confidence == "confirmed"
        assert rsa_findings[0].primitive == "pke"

    def test_detect_node_crypto_generate_ec(self):
        """Test detection of Node.js crypto.generateKeyPair for EC."""
        detector = JavaScriptSourceDetector()
        content = """
const crypto = require('crypto');
const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'secp256r1',
});
"""
        findings = detector.detect("test.js", content)
        ec_findings = [f for f in findings if f.name == "ECDSA"]
        assert len(ec_findings) >= 1
        assert ec_findings[0].confidence == "confirmed"
        assert ec_findings[0].primitive == "signature"

    def test_detect_node_crypto_generate_ed25519(self):
        """Test detection of Node.js crypto.generateKeyPair for Ed25519."""
        detector = JavaScriptSourceDetector()
        content = """
const crypto = require('crypto');
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
"""
        findings = detector.detect("test.js", content)
        ed_findings = [f for f in findings if f.name == "Ed25519"]
        assert len(ed_findings) >= 1
        assert ed_findings[0].confidence == "confirmed"
        assert ed_findings[0].primitive == "signature"

    def test_detect_node_crypto_create_sign(self):
        """Test detection of Node.js crypto.createSign."""
        detector = JavaScriptSourceDetector()
        content = """
const crypto = require('crypto');
const sign = crypto.createSign('RSA-SHA256');
"""
        findings = detector.detect("test.js", content)
        rsa_findings = [f for f in findings if f.name == "RSA" and f.primitive == "signature"]
        assert len(rsa_findings) >= 1
        assert rsa_findings[0].confidence == "confirmed"

    def test_detect_node_crypto_create_ecdh(self):
        """Test detection of Node.js crypto.createECDH."""
        detector = JavaScriptSourceDetector()
        content = """
const crypto = require('crypto');
const ecdh = crypto.createECDH('secp256r1');
"""
        findings = detector.detect("test.js", content)
        ecdh_findings = [f for f in findings if f.name == "ECDH"]
        assert len(ecdh_findings) >= 1
        assert ecdh_findings[0].confidence == "confirmed"
        assert ecdh_findings[0].primitive == "key-agree"

    def test_detect_web_crypto_ecdsa(self):
        """Test detection of Web Crypto API ECDSA."""
        detector = JavaScriptSourceDetector()
        content = """
const { subtle } = require('crypto').webcrypto;
const keyPair = await subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
);
"""
        findings = detector.detect("test.js", content)
        ecdsa_findings = [f for f in findings if f.name == "ECDSA"]
        assert len(ecdsa_findings) >= 1
        assert ecdsa_findings[0].confidence == "confirmed"
        assert ecdsa_findings[0].primitive == "signature"

    def test_detect_web_crypto_rsa_oaep(self):
        """Test detection of Web Crypto API RSA-OAEP."""
        detector = JavaScriptSourceDetector()
        content = """
const { subtle } = require('crypto').webcrypto;
const keyPair = await subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: 2048 },
    true,
    ['encrypt', 'decrypt']
);
"""
        findings = detector.detect("test.js", content)
        rsa_findings = [f for f in findings if f.name == "RSA" and f.primitive == "pke"]
        assert len(rsa_findings) >= 1
        assert rsa_findings[0].confidence == "confirmed"

    def test_detect_web_crypto_sign(self):
        """Test detection of Web Crypto API sign."""
        detector = JavaScriptSourceDetector()
        content = """
const { subtle } = require('crypto').webcrypto;
const signature = await subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    data
);
"""
        findings = detector.detect("test.js", content)
        ecdsa_findings = [f for f in findings if f.name == "ECDSA" and f.primitive == "signature"]
        assert len(ecdsa_findings) >= 1
        assert ecdsa_findings[0].confidence == "confirmed"

    def test_detect_web_crypto_verify(self):
        """Test detection of Web Crypto API verify."""
        detector = JavaScriptSourceDetector()
        content = """
const { subtle } = require('crypto').webcrypto;
const result = await subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    publicKey,
    signature,
    data
);
"""
        findings = detector.detect("test.js", content)
        ecdsa_findings = [f for f in findings if f.name == "ECDSA" and f.primitive == "signature"]
        assert len(ecdsa_findings) >= 1
        assert ecdsa_findings[0].confidence == "confirmed"

    def test_detect_jwt_rs256(self):
        """Test detection of jsonwebtoken RS256 algorithm."""
        detector = JavaScriptSourceDetector()
        content = """
const jwt = require('jsonwebtoken');
const token = jwt.sign(payload, privateKey, { algorithm: 'RS256' });
"""
        findings = detector.detect("test.js", content)
        rsa_findings = [f for f in findings if f.name == "RSA" and f.primitive == "signature"]
        assert len(rsa_findings) >= 1
        assert rsa_findings[0].confidence == "confirmed"

    def test_detect_jwt_es256(self):
        """Test detection of jsonwebtoken ES256 algorithm."""
        detector = JavaScriptSourceDetector()
        content = """
const jwt = require('jsonwebtoken');
const token = jwt.sign(payload, privateKey, { algorithm: 'ES256' });
"""
        findings = detector.detect("test.js", content)
        ecdsa_findings = [f for f in findings if f.name == "ECDSA"]
        assert len(ecdsa_findings) >= 1
        assert ecdsa_findings[0].confidence == "confirmed"

    def test_detect_jwt_hs256(self):
        """Test detection of jsonwebtoken HS256 algorithm."""
        detector = JavaScriptSourceDetector()
        content = """
const jwt = require('jsonwebtoken');
const token = jwt.sign(payload, secret, { algorithm: 'HS256' });
"""
        findings = detector.detect("test.js", content)
        hmac_findings = [f for f in findings if f.name == "HMAC"]
        assert len(hmac_findings) >= 1
        assert hmac_findings[0].confidence == "confirmed"

    def test_detect_import_statement(self):
        """Test detection with ES module imports."""
        detector = JavaScriptSourceDetector()
        content = """
import jwt from 'jsonwebtoken';
const token = jwt.sign(payload, privateKey, { algorithm: 'RS256' });
"""
        findings = detector.detect("test.js", content)
        rsa_findings = [f for f in findings if f.name == "RSA" and f.primitive == "signature"]
        assert len(rsa_findings) >= 1
        assert rsa_findings[0].confidence == "confirmed"

    def test_detect_typescript(self):
        """Test detection in TypeScript files."""
        detector = JavaScriptSourceDetector()
        content = """
import jwt from 'jsonwebtoken';
const token: string = jwt.sign(payload, privateKey, { algorithm: 'RS256' });
"""
        findings = detector.detect("test.ts", content)
        rsa_findings = [f for f in findings if f.name == "RSA" and f.primitive == "signature"]
        assert len(rsa_findings) >= 1
        assert rsa_findings[0].confidence == "confirmed"


class TestManifestDetectorJS:
    """Tests for ManifestDetector with package.json."""

    def test_detect_package_json_crypto_libs(self):
        """Test detection of crypto libraries in package.json."""
        from cbomscan.detectors.manifest import ManifestDetector
        detector = ManifestDetector()
        content = """
{
  "dependencies": {
    "jsonwebtoken": "^9.0.0",
    "node-forge": "^1.3.0",
    "elliptic": "^6.5.0"
  }
}
"""
        findings = detector.detect("package.json", content)
        names = {f.name for f in findings}
        assert "RSA" in names
        assert "ECDSA" in names
        assert "HMAC" in names

    def test_detect_package_json_confidence_inferred(self):
        """Test that package.json findings have inferred confidence."""
        from cbomscan.detectors.manifest import ManifestDetector
        detector = ManifestDetector()
        content = '{"dependencies": {"jsonwebtoken": "^9.0.0"}}'
        findings = detector.detect("package.json", content)
        for f in findings:
            assert f.confidence == "inferred"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
