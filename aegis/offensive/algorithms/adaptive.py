import cv2
import numpy as np
import struct
from PIL import Image
from math import floor

def get_texture_mask(image_array: np.ndarray) -> np.ndarray:
    """
    Returns a boolean mask of the image where True indicates high texture/edges.
    This uses Canny edge detection. Data will be hidden in these regions.
    """
    # Convert to grayscale for edge detection
    if len(image_array.shape) == 3:
        gray = cv2.cvtColor(image_array, cv2.COLOR_RGB2GRAY)
    else:
        gray = image_array
        
    # Apply Gaussian blur to reduce noise before edge detection
    blurred = cv2.GaussianBlur(gray, (3, 3), 0)
    
    # Canny Edge detection
    edges = cv2.Canny(blurred, threshold1=100, threshold2=200)
    
    # Dilate edges slightly to give us a bit more capacity near the edges
    kernel = np.ones((3,3), np.uint8)
    dilated_edges = cv2.dilate(edges, kernel, iterations=1)
    
    return dilated_edges > 0


def embed_adaptive(image_path: str, output_path: str, payload: bytes):
    """
    Adaptive spatial domain steganography. Embeds payload into the LSBs of
    highly textured areas of an image. Best for PNGs.
    """
    img = Image.open(image_path)
    img_array = np.array(img)
    
    if img_array.dtype != np.uint8:
        raise ValueError("Only 8-bit per channel images supported.")
        
    texture_mask = get_texture_mask(img_array)
    
    # Pack length + payload into bits
    length_bytes = struct.pack("<I", len(payload))
    full_payload = length_bytes + payload
    
    bits = np.unpackbits(np.frombuffer(full_payload, dtype=np.uint8))
    
    # Flatten everything for easier indexing
    flat_img = img_array.flatten()
    
    # We need to map the 2D texture mask to the flattened 1D array.
    # If the image has channels (e.g. RGB), the mask applies to all channels for a given pixel.
    num_channels = img_array.shape[2] if len(img_array.shape) == 3 else 1
    
    # Repeat mask for each channel
    flat_mask = np.repeat(texture_mask.flatten(), num_channels)
    
    changeable_indices = np.where(flat_mask)[0]
    
    if len(bits) > len(changeable_indices):
         raise ValueError(f"Payload too large. Capacity (bits) in textured regions: {len(changeable_indices)}, Required: {len(bits)}. Try a smaller payload or an image with more texture/details.")
         
    # Embed
    for i, bit in enumerate(bits):
        target_idx = changeable_indices[i]
        
        val = int(flat_img[target_idx])
        
        # Clear LSB
        val = val & 254
        # Set LSB to bit
        val = val | bit
        
        flat_img[target_idx] = np.uint8(val)
        
    # Reshape and save
    stego_img = Image.fromarray(flat_img.reshape(img_array.shape))
    stego_img.save(output_path, format="PNG")
    

def extract_adaptive(image_path: str) -> bytes:
    """
    Extracts payload from adaptive spatial domain steganography.
    """
    img = Image.open(image_path)
    img_array = np.array(img)
    
    texture_mask = get_texture_mask(img_array)
    num_channels = img_array.shape[2] if len(img_array.shape) == 3 else 1
    flat_mask = np.repeat(texture_mask.flatten(), num_channels)
    
    changeable_indices = np.where(flat_mask)[0]
    flat_img = img_array.flatten()
    
    if len(changeable_indices) < 32:
        return b""
        
    extracted_bits = []
    
    # Extract first 32 bits for length
    for i in range(32):
        target_idx = changeable_indices[i]
        extracted_bits.append(flat_img[target_idx] & 1)
        
    length_bits = np.array(extracted_bits, dtype=np.uint8)
    length_bytes = np.packbits(length_bits).tobytes()
    payload_len = struct.unpack("<I", length_bytes)[0]
    
    if payload_len > 10 * 1024 * 1024:
         return b""
         
    total_bits = 32 + (payload_len * 8)
    
    if total_bits > len(changeable_indices):
         return b""
         
    for i in range(32, total_bits):
        target_idx = changeable_indices[i]
        extracted_bits.append(flat_img[target_idx] & 1)
        
    full_bits = np.array(extracted_bits, dtype=np.uint8)
    full_bytes = np.packbits(full_bits).tobytes()
    
    return full_bytes[4:]
