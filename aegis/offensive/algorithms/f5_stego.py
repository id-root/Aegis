import numpy as np
import jpegio as jio
from typing import Tuple, List, Optional
import struct
import io

def get_changeable_dct_coeffs(dct_blocks: np.ndarray) -> np.ndarray:
    """
    Returns an array of tuples (channel, block_idx, coeff_idx) for DCT coefficients 
    that can be changed.
    In F5, we avoid DC coefficients (index 0) and coefficients that are 0.
    """
    # For a full JPEG, we have multiple channels (Y, Cb, Cr).
    # We will just collect all non-zero AC coefficients across all blocks.
    # dct_blocks is a list of arrays for each channel.
    
    changeables = []
    
    for c_idx, channel_dct in enumerate(dct_blocks):
        # channel_dct is shape (height_in_blocks * 8, width_in_blocks * 8)
        h, w = channel_dct.shape
        # We need to process block by block (8x8)
        for y in range(0, h, 8):
            for x in range(0, w, 8):
                block = channel_dct[y:y+8, x:x+8]
                # Flat indices 1-63 are AC coeffs. 0 is DC.
                flat_block = block.flatten()
                for i in range(1, 64):
                    if flat_block[i] != 0:
                         # Store global y, x, and block internal index
                         changeables.append((c_idx, y, x, i))
                         
    return changeables

def f5_embed_bit(channel_dct: np.ndarray, y: int, x: int, i: int, bit: int) -> int:
    """
    Embeds a single bit into a DCT coefficient in-place.
    Returns 1 if a shrinkage to 0 occurred (requiring re-embedding), else 0.
    """
    block = channel_dct[y:y+8, x:x+8]
    val = block.flatten()[i]
    
    if val == 0:
        return 1
        
    lsb = abs(val) & 1
    if lsb != bit:
        if val > 0:
            new_val = val - 1
        else:
            new_val = val + 1
            
        # Update block
        flat = block.flatten()
        flat[i] = new_val
        channel_dct[y:y+8, x:x+8] = flat.reshape((8,8))
        
        if new_val == 0:
            return 1
    return 0
    

def embed_f5_jpeg(image_path: str, output_path: str, payload: bytes):
    """
    Full F5 embedding directly modifying JPEG DCT coefficients.
    """
    try:
        jpeg = jio.read(image_path)
    except Exception as e:
        raise ValueError(f"Could not read JPEG for steganography: {e}")
        
    # Gather changeable coefficients
    changeables = get_changeable_dct_coeffs(jpeg.coef_arrays)
    
    length_bytes = struct.pack("<I", len(payload))
    full_payload = length_bytes + payload
    
    bits = np.unpackbits(np.frombuffer(full_payload, dtype=np.uint8))
    
    if len(bits) > len(changeables):
        raise ValueError(f"Payload too large. Capacity (bits): {len(changeables)}, Required: {len(bits)}")
        
    bit_idx = 0
    coeff_idx = 0
    
    # Simple linear embedding for now. 
    # Todo: PRNG permutation based on password for scattering.
    
    while bit_idx < len(bits):
        if coeff_idx >= len(changeables):
            raise ValueError("Hit capacity limit due to shrinkage.")
            
        c_idx, y, x, i = changeables[coeff_idx]
        bit = bits[bit_idx]
        
        shrinkage = f5_embed_bit(jpeg.coef_arrays[c_idx], y, x, i, bit)
        
        if shrinkage:
            coeff_idx += 1
        else:
            bit_idx += 1
            coeff_idx += 1
            
    try:
        jio.write(jpeg, output_path)
    except Exception as e:
         raise ValueError(f"Failed to write F5 stego JPEG: {e}")


def extract_f5_jpeg(image_path: str) -> bytes:
    """
    Extracts the payload from an F5-embedded JPEG by reading DCT coefficients.
    """
    try:
        jpeg = jio.read(image_path)
    except Exception as e:
        raise ValueError(f"Could not read JPEG for extraction: {e}")
        
    changeables = get_changeable_dct_coeffs(jpeg.coef_arrays)
    
    if len(changeables) < 32:
        return b"" # Too small
        
    extracted_bits = []
    
    coeff_idx = 0
    # First 32 bits for length
    while len(extracted_bits) < 32:
        if coeff_idx >= len(changeables):
             return b""
        c_idx, y, x, i = changeables[coeff_idx]
        val = jpeg.coef_arrays[c_idx][y:y+8, x:x+8].flatten()[i]
        
        if val != 0:
            extracted_bits.append(abs(val) & 1)
        coeff_idx += 1
        
    length_bits = np.array(extracted_bits, dtype=np.uint8)
    length_bytes = np.packbits(length_bits).tobytes()
    payload_len = struct.unpack("<I", length_bytes)[0]
    
    # Sanity check length
    if payload_len > 10 * 1024 * 1024: # max 10mb
         return b""
         
    total_bits_needed = 32 + (payload_len * 8)
    
    while len(extracted_bits) < total_bits_needed:
        if coeff_idx >= len(changeables):
            break 
        c_idx, y, x, i = changeables[coeff_idx]
        val = jpeg.coef_arrays[c_idx][y:y+8, x:x+8].flatten()[i]
        
        if val != 0:
            extracted_bits.append(abs(val) & 1)
        coeff_idx += 1
        
    if len(extracted_bits) < total_bits_needed:
         return b""
         
    full_bits = np.array(extracted_bits, dtype=np.uint8)
    full_bytes = np.packbits(full_bits).tobytes()
    
    return full_bytes[4:] # Strip length header
