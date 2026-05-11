import hmac
import hashlib
from typing import Tuple

def sign_image_hash(image_hash: str, secret_key: str) -> str:
    """
    Signs a cryptographic hash using HMAC-SHA256 and a secret key.
    """
    h = hmac.new(secret_key.encode('utf-8'), image_hash.encode('utf-8'), hashlib.sha256)
    return h.hexdigest()

def verify_image_signature(image_hash: str, signature: str, secret_key: str) -> bool:
    """
    Verifies that the given signature matches the image hash and secret key.
    """
    expected_signature = sign_image_hash(image_hash, secret_key)
    return hmac.compare_digest(expected_signature, signature)

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
import base64

def generate_key_pair() -> Tuple[bytes, bytes]:
    """
    Generates an Ed25519 key pair for asymmetric signing.
    Returns (private_key_pem, public_key_pem).
    """
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return priv_pem, pub_pem

def sign_image_hash_asymmetric(image_hash: str, private_key_pem: bytes) -> str:
    """
    Signs a cryptographic hash using Ed25519 and a private key.
    Returns a base64-encoded signature.
    """
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None
    )
    # The image_hash is a hex string. We sign the bytes representation of it.
    signature = private_key.sign(image_hash.encode('utf-8'))
    return base64.b64encode(signature).decode('utf-8')

def verify_image_signature_asymmetric(image_hash: str, signature_b64: str, public_key_pem: bytes) -> bool:
    """
    Verifies that the given Ed25519 signature matches the image hash and public key.
    """
    try:
        public_key = serialization.load_pem_public_key(public_key_pem)
        signature_bytes = base64.b64decode(signature_b64)
        public_key.verify(signature_bytes, image_hash.encode('utf-8'))
        return True
    except (InvalidSignature, ValueError):
        return False

