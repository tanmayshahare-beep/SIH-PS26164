"""Test file with crypto usage for CBOMScan fixture."""

import hashlib
import ssl
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def weak_hash_example():
    """Example using weak hash algorithms."""
    # MD5 - broken
    data = b"test data"
    md5_hash = hashlib.md5(data).hexdigest()
    print(f"MD5: {md5_hash}")

    # SHA1 - broken
    sha1_hash = hashlib.sha1(data).hexdigest()
    print(f"SHA1: {sha1_hash}")

    return md5_hash, sha1_hash


def strong_hash_example():
    """Example using strong hash algorithms."""
    data = b"test data"
    sha256_hash = hashlib.sha256(data).hexdigest()
    sha384_hash = hashlib.sha384(data).hexdigest()
    sha512_hash = hashlib.sha512(data).hexdigest()
    return sha256_hash, sha384_hash, sha512_hash


def rsa_keygen_example():
    """Example RSA key generation."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key


def ec_keygen_example():
    """Example EC key generation."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


def ed25519_keygen_example():
    """Example Ed25519 key generation."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def cipher_example():
    """Example cipher usage."""
    key = b"0123456789abcdef0123456789abcdef"  # 32 bytes for AES-256
    iv = b"0123456789abcdef"  # 16 bytes
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    return cipher


def pbkdf2_example():
    """Example PBKDF2 usage."""
    kdf = PBKDF2(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"salt",
        iterations=100000,
    )
    key = kdf.derive(b"password")
    return key


def ssl_context_example():
    """Example SSL context creation."""
    context = ssl.create_default_context()
    return context


if __name__ == "__main__":
    weak_hash_example()
    strong_hash_example()
    rsa_keygen_example()
    ec_keygen_example()
    ed25519_keygen_example()
    cipher_example()
    pbkdf2_example()
    ssl_context_example()
    print("All crypto examples executed")