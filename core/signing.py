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

def generate_key_pair() -> Tuple[str, str]:
    """
    For a fully asymmetric implementation, we'd use RSA/ECC.
    Here we return a simple symmetric secret as a placeholder.
    In real app, we'd use `cryptography` module to generate RSA keys.
    """
    import secrets
    secret = secrets.token_hex(32)
    return secret, secret
