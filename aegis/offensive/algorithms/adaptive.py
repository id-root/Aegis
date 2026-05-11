"""
Adaptive Spatial-Domain Steganography — v2

Upgraded from v1 (Canny edge mask + raw LSB) to a cost-function-driven
framework with Syndrome-Trellis Code (STC) embedding.

Embedding pipeline:
    1. Compute pixel-wise cost map (HILL / WOW / MiPOD)
    2. Select embeddable positions (sort by cost, lowest-first)
    3. Embed using STC for near-optimal distortion minimisation
    4. Ternary modifications (+1, 0, -1) for lower detectability

Backward compatibility:
    The v1 Canny-mask functions are retained under `_legacy_*` names.
"""

import cv2
import numpy as np
import struct
from PIL import Image
from typing import Optional

from aegis.offensive.algorithms.cost_functions import get_cost_map, COST_FUNCTIONS
from aegis.offensive.algorithms.stc_embed import STCEngine


# ═══════════════════════════════════════════════════════════════════════════
#  Legacy v1 Functions (kept for backward compat)
# ═══════════════════════════════════════════════════════════════════════════

def get_texture_mask(image_array: np.ndarray) -> np.ndarray:
    """
    Returns a boolean mask of the image where True indicates high texture/edges.
    This uses Canny edge detection. Data will be hidden in these regions.
    
    CRITICAL: We mask out the LSB (apply & 0xFE) BEFORE computing edges.
    This ensures the mask is invariant to our LSB modifications, guaranteeing
    that the exact same mask is produced during both embedding and extraction.
    """
    # Mask out LSBs to make edge detection invariant to our modifications
    stable_array = image_array & 0xFE
    
    # Convert to grayscale for edge detection
    if len(stable_array.shape) == 3:
        gray = cv2.cvtColor(stable_array, cv2.COLOR_RGB2GRAY)
    else:
        gray = stable_array
        
    # Apply Gaussian blur to reduce noise before edge detection
    blurred = cv2.GaussianBlur(gray, (3, 3), 0)
    
    # Canny Edge detection
    edges = cv2.Canny(blurred, threshold1=100, threshold2=200)
    
    # Dilate edges slightly to give us a bit more capacity near the edges
    kernel = np.ones((3,3), np.uint8)
    dilated_edges = cv2.dilate(edges, kernel, iterations=1)
    
    return dilated_edges > 0


def _legacy_embed(image_path: str, output_path: str, payload: bytes):
    """Legacy v1 embedding using Canny mask + raw LSB."""
    img = Image.open(image_path)
    img_array = np.array(img)
    
    if img_array.dtype != np.uint8:
        raise ValueError("Only 8-bit per channel images supported.")
        
    texture_mask = get_texture_mask(img_array)
    
    length_bytes = struct.pack("<I", len(payload))
    full_payload = length_bytes + payload
    bits = np.unpackbits(np.frombuffer(full_payload, dtype=np.uint8))
    
    flat_img = img_array.flatten()
    num_channels = img_array.shape[2] if len(img_array.shape) == 3 else 1
    flat_mask = np.repeat(texture_mask.flatten(), num_channels)
    changeable_indices = np.where(flat_mask)[0]
    
    if len(bits) > len(changeable_indices):
        raise ValueError(
            f"Payload too large. Capacity (bits) in textured regions: "
            f"{len(changeable_indices)}, Required: {len(bits)}."
        )
         
    for i, bit in enumerate(bits):
        target_idx = changeable_indices[i]
        val = int(flat_img[target_idx])
        val = (val & 254) | bit
        flat_img[target_idx] = np.uint8(val)
        
    stego_img = Image.fromarray(flat_img.reshape(img_array.shape))
    stego_img.save(output_path, format="PNG")


def _legacy_extract(image_path: str) -> bytes:
    """Legacy v1 extraction using Canny mask + raw LSB."""
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


# ═══════════════════════════════════════════════════════════════════════════
#  v2 — Cost-Function + STC Embedding
# ═══════════════════════════════════════════════════════════════════════════

def _build_position_order(cost_map: np.ndarray, image_shape: tuple) -> np.ndarray:
    """
    Build an ordered list of (flat) pixel indices sorted by embedding cost.
    
    We only consider positions where cost is below a threshold (top 70% of
    capacity) to avoid embedding in completely flat regions.
    
    Returns flat indices into the image array.
    """
    h, w = cost_map.shape[:2]
    flat_cost = cost_map.flatten()
    
    # Sort by cost (ascending = cheapest first)
    sorted_indices = np.argsort(flat_cost)
    
    # Filter out positions with infinite or extremely high cost
    max_cost = np.percentile(flat_cost[np.isfinite(flat_cost)], 95)
    valid = flat_cost[sorted_indices] <= max_cost
    
    return sorted_indices[valid]


def embed_adaptive(image_path: str, output_path: str, payload: bytes,
                   cost_method: str = "hill", stc_h: int = 10,
                   use_legacy: bool = False):
    """
    Embed payload using adaptive spatial-domain steganography.
    
    Parameters
    ----------
    image_path : str
        Path to the cover PNG image.
    output_path : str
        Path for the stego PNG output.
    payload : bytes
        Raw ciphertext to embed.
    cost_method : str
        Cost function: 'hill', 'wow', or 'mipod'. Default 'hill'.
    stc_h : int
        STC trellis width. Higher = better quality, slower. Default 10.
    use_legacy : bool
        If True, use v1 Canny+LSB embedding (for backward compatibility).
    """
    if use_legacy:
        return _legacy_embed(image_path, output_path, payload)
    
    img = Image.open(image_path)
    img_array = np.array(img)
    
    if img_array.dtype != np.uint8:
        raise ValueError("Only 8-bit per channel images supported.")
    
    # 1. Compute cost map from LSB-masked image (ensures same map on extract)
    #    Masking out LSBs (& 0xFE) makes the cost invariant to our ±1 mods,
    #    guaranteeing the extractor computes the same sort order.
    stable_array = img_array & 0xFE
    cost_map = get_cost_map(stable_array, method=cost_method)
    
    # 2. Build position order (cheapest to modify first)
    if img_array.ndim == 3:
        num_channels = img_array.shape[2]
        cost_expanded = np.repeat(cost_map.flatten(), num_channels)
    else:
        num_channels = 1
        cost_expanded = cost_map.flatten()
    
    flat_img = img_array.flatten()
    flat_stable = stable_array.flatten()
    sorted_indices = np.argsort(cost_expanded, kind='stable')
    
    # Filter valid positions using LSB-masked values (stable across embed/extract)
    valid_mask = (flat_stable[sorted_indices] > 0) & (flat_stable[sorted_indices] < 254)
    embeddable_indices = sorted_indices[valid_mask]
    
    # 3. Prepare payload bitstream
    length_bytes = struct.pack("<I", len(payload))
    length_bits = np.unpackbits(np.frombuffer(length_bytes, dtype=np.uint8))
    payload_bits = np.unpackbits(np.frombuffer(payload, dtype=np.uint8))
    
    # Total positions needed:
    # - 32 positions for raw-LSB length header
    # - payload_bits * 3 positions for STC body (3x margin for block code)
    header_positions = 32
    body_stc_positions = min(
        len(embeddable_indices) - header_positions,
        max(len(payload_bits), len(payload_bits) * 3)
    )
    total_needed = header_positions + len(payload_bits)
    
    if total_needed > len(embeddable_indices):
        raise ValueError(
            f"Payload too large. Capacity: {len(embeddable_indices) - header_positions} bits, "
            f"Required: {len(payload_bits)} bits. Try a smaller payload or larger image."
        )
    
    # 4. Embed length header as raw LSBs in the first 32 positions
    header_indices = embeddable_indices[:header_positions]
    for i, bit in enumerate(length_bits):
        idx = header_indices[i]
        val = int(flat_img[idx])
        flat_img[idx] = (val & 0xFE) | int(bit)
    
    # 5. Embed payload body using STC in the remaining positions
    stc_indices = embeddable_indices[header_positions:]
    n_stc_positions = min(len(stc_indices), len(payload_bits) * 3)
    
    if n_stc_positions < len(payload_bits):
        raise ValueError(
            f"Payload too large for STC. Available: {n_stc_positions}, "
            f"Required: {len(payload_bits)} bits."
        )
    
    stc_positions = stc_indices[:n_stc_positions]
    cover_values = flat_img[stc_positions].copy()
    position_costs = cost_expanded[stc_positions]
    
    engine = STCEngine(h=stc_h)
    stego_values, distortion = engine.embed(cover_values, position_costs, payload_bits)
    
    # 6. Write back
    flat_img[stc_positions] = stego_values
    stego_img = Image.fromarray(flat_img.reshape(img_array.shape))
    stego_img.save(output_path, format="PNG")


def extract_adaptive(image_path: str, cost_method: str = "hill",
                     stc_h: int = 10, use_legacy: bool = False) -> bytes:
    """
    Extract payload from adaptive spatial-domain steganography.
    
    Parameters
    ----------
    image_path : str
        Path to the stego PNG image.
    cost_method : str
        Cost function used during embedding. Must match.
    stc_h : int
        STC trellis width used during embedding. Must match.
    use_legacy : bool
        If True, use v1 Canny+LSB extraction.
    """
    if use_legacy:
        return _legacy_extract(image_path)
    
    img = Image.open(image_path)
    img_array = np.array(img)
    
    # 1. Recompute cost map from LSB-masked image (same as embedding)
    stable_array = img_array & 0xFE
    cost_map = get_cost_map(stable_array, method=cost_method)
    
    if img_array.ndim == 3:
        num_channels = img_array.shape[2]
        cost_expanded = np.repeat(cost_map.flatten(), num_channels)
    else:
        num_channels = 1
        cost_expanded = cost_map.flatten()
    
    flat_img = img_array.flatten()
    flat_stable = stable_array.flatten()
    sorted_indices = np.argsort(cost_expanded, kind='stable')
    
    valid_mask = (flat_stable[sorted_indices] > 0) & (flat_stable[sorted_indices] < 254)
    embeddable_indices = sorted_indices[valid_mask]
    
    header_positions = 32
    if len(embeddable_indices) < header_positions:
        return b""
    
    # 2. Read the 32-bit length header from raw LSBs
    header_indices = embeddable_indices[:header_positions]
    header_bits = np.array([flat_img[idx] & 1 for idx in header_indices], dtype=np.uint8)
    length_bytes = np.packbits(header_bits).tobytes()
    payload_len = struct.unpack("<I", length_bytes)[0]
    
    if payload_len == 0 or payload_len > 10 * 1024 * 1024:
        return b""
    
    payload_bits_count = payload_len * 8
    
    # 3. Extract payload body using STC
    stc_indices = embeddable_indices[header_positions:]
    n_stc_positions = min(len(stc_indices), payload_bits_count * 3)
    
    if n_stc_positions < payload_bits_count:
        return b""
    
    stc_positions = stc_indices[:n_stc_positions]
    stc_values = flat_img[stc_positions]
    
    engine = STCEngine(h=stc_h)
    payload_bits = engine.extract(stc_values, payload_bits_count)
    
    payload_bytes = np.packbits(payload_bits).tobytes()
    
    return payload_bytes[:payload_len]
