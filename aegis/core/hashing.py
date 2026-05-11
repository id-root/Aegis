import hashlib
from typing import Optional
from PIL import Image

def generate_crypto_hash(data: bytes, algorithm: str = "sha256") -> str:
    """Generates a cryptographic hash of the given byte data."""
    hasher = hashlib.new(algorithm)
    hasher.update(data)
    return hasher.hexdigest()

def generate_file_hash(filepath: str, algorithm: str = "sha256") -> str:
    """Generates a cryptographic hash of a file."""
    hasher = hashlib.new(algorithm)
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()

def generate_perceptual_hash(image: Image.Image, hash_size: int = 8) -> str:
    """
    Generates a basic difference hash (dHash) for an image.
    Useful for detecting similar images despite minor structural changes.
    """
    # Convert to grayscale and resize to (hash_size + 1, hash_size)
    image = image.convert("L").resize((hash_size + 1, hash_size), Image.Resampling.LANCZOS)
    pixels = list(image.getdata())
    
    diff = []
    for row in range(hash_size):
        for col in range(hash_size):
            pixel_left = image.getpixel((col, row))
            pixel_right = image.getpixel((col + 1, row))
            diff.append(pixel_left > pixel_right)
    
    # Convert binary array to hex string
    decimal_value = 0
    hex_string = []
    for index, value in enumerate(diff):
        if value:
            decimal_value += 2**(index % 8)
        if (index % 8) == 7:
            hex_string.append(hex(decimal_value)[2:].rjust(2, '0'))
            decimal_value = 0
            
    return ''.join(hex_string)
