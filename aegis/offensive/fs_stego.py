import os

XATTR_NAME = "user.aegis_payload"

def embed_xattr(file_path: str, payload: bytes) -> bool:
    """
    Embeds a raw payload into the file's Extended Attributes (xattr).
    This allows hiding data within the file system metadata without 
    modifying the file's actual content or its cryptographic hash.
    
    Args:
        file_path: Path to the carrier file.
        payload: The raw bytes to hide.
        
    Returns:
        True if successful.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
        
    try:
        # Note: Depending on the filesystem, xattrs might have size limits (e.g., 4KB on ext4 by default).
        # We catch OS errors related to size limits here.
        os.setxattr(file_path, XATTR_NAME, payload)
        return True
    except OSError as e:
        raise RuntimeError(f"Failed to embed into xattr (payload might be too large for the filesystem): {e}")

def extract_xattr(file_path: str) -> bytes:
    """
    Extracts a payload from the file's Extended Attributes (xattr).
    
    Args:
        file_path: Path to the carrier file.
        
    Returns:
        The extracted payload bytes, or None if not found.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
        
    try:
        if XATTR_NAME in os.listxattr(file_path):
            return os.getxattr(file_path, XATTR_NAME)
        return b""
    except OSError as e:
        raise RuntimeError(f"Failed to extract from xattr: {e}")
