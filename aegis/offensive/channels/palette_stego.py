"""
Palette-Based Steganography — Colour Table Reordering

Hides data by manipulating the order of entries in a palette-based image
(PNG-8, GIF).  The pixel indices are remapped so the visual output is
identical but the raw palette order encodes the message.

Technique
---------
Given a palette with N colours, there are N! possible orderings.  We use
the Lehmer code to bijectively map between a large integer (the message)
and a permutation of the palette.  For a 256-colour palette this gives
log2(256!) ≈ 1684 bits of capacity — enough for ~210 bytes per image.

Security
--------
- The pixel data is visually identical (same colour at every pixel)
- SHA-256 of the rendered pixels is UNCHANGED
- Only the raw palette order differs — invisible to any pixel analyser
- Password-seeded shuffling adds an extra permutation layer for security

Reconstruction Strategy
-----------------------
Both embedder and extractor derive a **canonical ordering** of the used
palette colours by sorting their RGB tuples.  The embedder encodes the
message as a permutation of this canonical order and writes the permuted
palette.  The extractor reads the current palette, re-derives the
canonical sort, and recovers the permutation via ranking.
"""

import numpy as np
import struct
import hashlib
from PIL import Image
from typing import Tuple
from math import factorial, log2


def _lehmer_encode(permutation: list) -> int:
    """
    Encode a permutation as a Lehmer code (factorial number system).
    
    Returns a unique integer in [0, n!) representing the permutation.
    """
    n = len(permutation)
    code = 0
    available = list(range(n))
    
    for i in range(n):
        idx = available.index(permutation[i])
        code = code * (n - i) + idx
        available.pop(idx)
    
    return code


def _lehmer_decode(code: int, n: int) -> list:
    """
    Decode a Lehmer code integer back to a permutation of [0, n-1].
    """
    available = list(range(n))
    permutation = []
    
    for i in range(n):
        factorial_val = factorial(n - 1 - i)
        idx = code // factorial_val
        code = code % factorial_val
        
        if idx >= len(available):
            idx = len(available) - 1
        
        permutation.append(available[idx])
        available.pop(idx)
    
    return permutation


def _int_to_bytes(value: int, length: int) -> bytes:
    """Convert a large integer to bytes (big-endian)."""
    result = []
    for _ in range(length):
        result.append(value & 0xFF)
        value >>= 8
    return bytes(reversed(result))


def _bytes_to_int(data: bytes) -> int:
    """Convert bytes to a large integer (big-endian)."""
    result = 0
    for b in data:
        result = (result << 8) | b
    return result


def _get_canonical_order(palette_entries: list, n_colours: int) -> list:
    """
    Derive a canonical ordering of palette slots by sorting their RGB tuples.
    
    Returns a list of original slot indices sorted by their (R, G, B) value.
    Ties are broken by original index to ensure uniqueness.
    """
    indexed = [(palette_entries[i], i) for i in range(n_colours)]
    indexed.sort(key=lambda x: (x[0], x[1]))
    return [orig_idx for _, orig_idx in indexed]


def embed_palette(image_path: str, output_path: str, payload: bytes,
                  password: str = "") -> None:
    """
    Embed a payload by reordering the colour palette.
    
    Parameters
    ----------
    image_path : str
        Path to a palette-based image (PNG-8, GIF).
    output_path : str
        Path for the output image.
    payload : bytes
        Data to embed (max ~210 bytes for 256-colour palette).
    password : str
        Optional password for additional security.
    """
    img = Image.open(image_path)
    
    # Convert to palette mode if not already
    if img.mode != 'P':
        img = img.quantize(colors=256)
    
    palette = img.getpalette()
    if palette is None:
        raise ValueError("Image has no palette.")
    
    # Get pixel data and unique palette indices actually used
    pixel_data = np.array(img)
    unique_indices = np.unique(pixel_data)
    n_colours = len(unique_indices)
    
    if n_colours < 4:
        raise ValueError(f"Need at least 4 palette entries, got {n_colours}.")
    
    # Capacity in bits
    capacity_bits = int(log2(factorial(n_colours)))
    capacity_bytes = capacity_bits // 8 - 4  # subtract 4 for length header
    
    if len(payload) > capacity_bytes:
        raise ValueError(
            f"Payload too large. Capacity: {capacity_bytes} bytes for "
            f"{n_colours}-colour palette. Payload: {len(payload)} bytes."
        )
    
    # Build the message integer
    length_bytes = struct.pack("<I", len(payload))
    message_bytes = length_bytes + payload
    
    # Pad to capacity
    padded = message_bytes + b'\x00' * (capacity_bytes + 4 - len(message_bytes))
    message_int = _bytes_to_int(padded)
    
    # Get the original palette entries for used colours
    old_palette = list(zip(palette[0::3], palette[1::3], palette[2::3]))
    used_entries = [old_palette[unique_indices[i]] for i in range(n_colours)]
    
    # Derive canonical order by sorting RGB tuples
    canonical_order = _get_canonical_order(used_entries, n_colours)
    # canonical_order[rank] = original slot index (in used_entries)
    
    # Apply password-seeded shuffle to the canonical order
    if password:
        seed = int.from_bytes(
            hashlib.sha256(password.encode()).digest()[:4], 'little'
        )
        rng = np.random.RandomState(seed)
        shuffled = rng.permutation(n_colours).tolist()
        # Re-order canonical: apply shuffle
        canonical_order = [canonical_order[shuffled[i]] for i in range(n_colours)]
    
    # Convert message to a permutation via Lehmer code
    max_code = factorial(n_colours)
    if message_int >= max_code:
        raise ValueError("Message integer exceeds permutation space.")
    
    message_perm = _lehmer_decode(message_int, n_colours)
    
    # The final palette order: message_perm selects from the canonical order
    # final_order[i] = which used_entries slot goes to palette position i
    final_order = [canonical_order[message_perm[i]] for i in range(n_colours)]
    
    # Build new palette: position i gets the colour from used_entries[final_order[i]]
    new_palette_entries = [used_entries[final_order[i]] for i in range(n_colours)]
    
    # Build full 256-colour palette
    full_palette = [0] * 768
    for i, (r, g, b) in enumerate(new_palette_entries):
        full_palette[i * 3] = r
        full_palette[i * 3 + 1] = g
        full_palette[i * 3 + 2] = b
    
    # Remap pixel data: old pixel index → new palette position
    # Build mapping: used_entries slot → new palette position
    slot_to_new_pos = [0] * n_colours
    for new_pos, slot in enumerate(final_order):
        slot_to_new_pos[slot] = new_pos
    
    new_pixels = pixel_data.copy()
    for slot_idx, orig_pixel_val in enumerate(unique_indices):
        mask = pixel_data == orig_pixel_val
        new_pixels[mask] = slot_to_new_pos[slot_idx]
    
    # Create output image
    out_img = Image.fromarray(new_pixels, mode='P')
    out_img.putpalette(full_palette)
    out_img.save(output_path)


def extract_palette(image_path: str, password: str = "") -> bytes:
    """
    Extract payload from palette ordering.
    
    Parameters
    ----------
    image_path : str
        Path to the stego palette image.
    password : str
        Same password used during embedding.
    
    Returns
    -------
    bytes : The extracted payload.
    """
    img = Image.open(image_path)
    
    if img.mode != 'P':
        raise ValueError("Image is not palette-based.")
    
    palette = img.getpalette()
    if palette is None:
        return b""
    
    pixel_data = np.array(img)
    unique_indices = np.unique(pixel_data)
    n_colours = len(unique_indices)
    
    if n_colours < 4:
        return b""
    
    capacity_bits = int(log2(factorial(n_colours)))
    capacity_bytes = capacity_bits // 8 - 4
    
    # Read the current palette entries (in stego order)
    current_palette = list(zip(palette[0::3], palette[1::3], palette[2::3]))
    stego_entries = [current_palette[i] for i in range(n_colours)]
    
    # Derive the same canonical order from the stego palette entries
    # (sorting by RGB gives the same result regardless of palette order)
    canonical_order = _get_canonical_order(stego_entries, n_colours)
    # canonical_order[rank] = stego position
    
    # Apply the same password shuffle
    if password:
        seed = int.from_bytes(
            hashlib.sha256(password.encode()).digest()[:4], 'little'
        )
        rng = np.random.RandomState(seed)
        shuffled = rng.permutation(n_colours).tolist()
        canonical_order = [canonical_order[shuffled[i]] for i in range(n_colours)]
    
    # Recover the permutation: for each canonical slot, what position is it in?
    # canonical_order[rank] = stego_position
    # We need: perm such that canonical_order[perm[i]] = i (for position i)
    # i.e. perm[stego_position] = rank → the inverse of canonical_order
    inv_canonical = [0] * n_colours
    for rank, stego_pos in enumerate(canonical_order):
        inv_canonical[stego_pos] = rank
    
    # The permutation that was applied: perm[i] = inv_canonical[i]
    # This is the message_perm from embedding
    message_perm = [inv_canonical[i] for i in range(n_colours)]
    
    # Lehmer-encode to recover the message integer
    message_int = _lehmer_encode(message_perm)
    
    # Convert integer to bytes
    message_bytes = _int_to_bytes(message_int, capacity_bytes + 4)
    
    # Extract length
    if len(message_bytes) < 4:
        return b""
    
    payload_len = struct.unpack("<I", message_bytes[:4])[0]
    
    if payload_len > len(message_bytes) - 4 or payload_len > 10 * 1024 * 1024:
        return b""
    
    return message_bytes[4:4 + payload_len]
