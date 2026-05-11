"""
Multi-Carrier Payload Splitting — Shamir's (k, n) Secret Sharing

Splits a payload into n shares such that any k shares can reconstruct
the original, but k-1 shares reveal nothing.  Each share is then
embedded into a separate carrier image using any available algorithm.

This provides:
  - **Redundancy**: Lose up to n-k carriers and still recover
  - **Security**: No single carrier contains recoverable data
  - **Flexibility**: Mix algorithms (F5 on JPEG, adaptive on PNG)

The implementation uses Shamir's Secret Sharing over GF(2^8) with an
irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11B).
"""

import os
import struct
import hashlib
import secrets
from typing import List, Tuple


# ═══════════════════════════════════════════════════════════════════════════
#  GF(2^8) Arithmetic
# ═══════════════════════════════════════════════════════════════════════════

# Irreducible polynomial: x^8 + x^4 + x^3 + x + 1
_GF_POLY = 0x11B

# Precompute log/exp tables for fast multiplication
_EXP_TABLE = [0] * 512
_LOG_TABLE = [0] * 256

def _init_gf_tables():
    """Build GF(2^8) log and exp lookup tables using generator 3.

    Generator 3 (x + 1) is a primitive element of GF(2^8) with the AES
    polynomial x^8 + x^4 + x^3 + x + 1 (0x11B), meaning it has
    multiplicative order 255 and generates all non-zero field elements.

    NOTE: The original code used generator 2 (left-shift), which only has
    order 51 for this polynomial and produces only 51 of the 255 non-zero
    elements.  That made every GF multiplication, and therefore all of
    Shamir's Secret Sharing, silently wrong.
    """
    x = 1
    for i in range(255):
        _EXP_TABLE[i] = x
        _LOG_TABLE[x] = i
        # Multiply x by generator 3 in GF(2^8):
        #   x * 3 = x * (2 + 1) = gf_double(x) ^ x
        doubled = (x << 1) ^ (0x1B if x & 0x80 else 0)
        x = (doubled ^ x) & 0xFF
    # Extend exp table for easy mod-free indexing
    for i in range(255, 512):
        _EXP_TABLE[i] = _EXP_TABLE[i - 255]

_init_gf_tables()


def _gf_mul(a: int, b: int) -> int:
    """Multiply two elements in GF(2^8)."""
    if a == 0 or b == 0:
        return 0
    return _EXP_TABLE[_LOG_TABLE[a] + _LOG_TABLE[b]]


def _gf_div(a: int, b: int) -> int:
    """Divide a by b in GF(2^8)."""
    if b == 0:
        raise ZeroDivisionError("Division by zero in GF(2^8)")
    if a == 0:
        return 0
    return _EXP_TABLE[(_LOG_TABLE[a] - _LOG_TABLE[b]) % 255]


def _gf_pow(a: int, exp: int) -> int:
    """Raise a to the power exp in GF(2^8)."""
    if exp == 0:
        return 1
    if a == 0:
        return 0
    return _EXP_TABLE[(_LOG_TABLE[a] * exp) % 255]


# ═══════════════════════════════════════════════════════════════════════════
#  Shamir's Secret Sharing
# ═══════════════════════════════════════════════════════════════════════════

def split_secret(data: bytes, k: int, n: int) -> List[Tuple[int, bytes]]:
    """
    Split `data` into `n` shares using Shamir's (k, n) secret sharing.
    
    Parameters
    ----------
    data : bytes
        The secret payload to split.
    k : int
        Minimum number of shares needed to reconstruct. Must be >= 2.
    n : int
        Total number of shares to generate. Must be >= k and <= 255.
    
    Returns
    -------
    List of (share_id, share_bytes) tuples, where share_id ∈ [1, n].
    Each share is the same length as `data` plus a 12-byte header:
        [magic: 4B] [k: 1B] [n: 1B] [share_id: 1B] [reserved: 1B] [data_len: 4B]
    """
    if k < 2:
        raise ValueError("Threshold k must be >= 2")
    if n < k:
        raise ValueError(f"n ({n}) must be >= k ({k})")
    if n > 255:
        raise ValueError("n must be <= 255 (GF(2^8) constraint)")
    
    data_len = len(data)
    
    # For each byte of the secret, generate ONE random polynomial of degree k-1
    # where the constant term is the secret byte.  All shares are points on
    # the SAME polynomial — this is the fundamental Shamir invariant.
    
    # Pre-generate polynomials (one per byte of the secret)
    polys = []
    for byte_idx in range(data_len):
        secret_byte = data[byte_idx]
        # f(x) = a_0 + a_1*x + ... + a_{k-1}*x^{k-1},  a_0 = secret_byte
        coeffs = [secret_byte]
        for _ in range(k - 1):
            coeffs.append(secrets.randbelow(256))
        polys.append(coeffs)
    
    # Evaluate every polynomial at x = share_idx for each share
    shares = []
    for share_idx in range(1, n + 1):
        share_data = bytearray(data_len)
        
        for byte_idx in range(data_len):
            coeffs = polys[byte_idx]
            val = 0
            for power, coeff in enumerate(coeffs):
                val ^= _gf_mul(coeff, _gf_pow(share_idx, power))
            
            share_data[byte_idx] = val
        
        # Pack header
        header = struct.pack("<4sBBBBI",
                           b"SHSS",  # Magic: Shamir Share
                           k, n, share_idx, 0,
                           data_len)
        
        shares.append((share_idx, bytes(header) + bytes(share_data)))
    
    return shares


def reconstruct_secret(shares: List[Tuple[int, bytes]]) -> bytes:
    """
    Reconstruct the secret from k or more shares using Lagrange interpolation.
    
    Parameters
    ----------
    shares : list of (share_id, share_bytes) tuples
        At least k shares (as returned by split_secret).
    
    Returns
    -------
    bytes : The reconstructed secret.
    """
    if len(shares) < 2:
        raise ValueError("Need at least 2 shares to reconstruct")
    
    # Parse headers
    parsed = []
    k_val = None
    data_len = None
    
    for share_id, share_bytes in shares:
        if len(share_bytes) < 12:
            raise ValueError(f"Share {share_id} is too short")
        
        magic, k, n, sid, _, dlen = struct.unpack("<4sBBBBI", share_bytes[:12])
        
        if magic != b"SHSS":
            raise ValueError(f"Share {share_id} has invalid magic bytes")
        
        if k_val is None:
            k_val = k
            data_len = dlen
        else:
            if k != k_val or dlen != data_len:
                raise ValueError("Shares have inconsistent parameters")
        
        parsed.append((sid, share_bytes[12:12 + data_len]))
    
    if len(parsed) < k_val:
        raise ValueError(
            f"Need {k_val} shares to reconstruct, but only {len(parsed)} provided"
        )
    
    # Use exactly k_val shares (first k)
    used_shares = parsed[:k_val]
    x_coords = [s[0] for s in used_shares]
    
    # Lagrange interpolation at x=0 for each byte position
    secret = bytearray(data_len)
    
    for byte_idx in range(data_len):
        y_values = [s[1][byte_idx] for s in used_shares]
        
        # Evaluate the Lagrange interpolation at x=0
        result = 0
        for i in range(k_val):
            # Compute Lagrange basis polynomial L_i(0)
            numerator = 1
            denominator = 1
            
            for j in range(k_val):
                if i != j:
                    # L_i(0) = product of (0 - x_j) / (x_i - x_j)
                    # In GF(2^8): 0 - x_j = x_j (additive inverse = itself)
                    numerator = _gf_mul(numerator, x_coords[j])
                    denominator = _gf_mul(denominator, x_coords[i] ^ x_coords[j])
            
            # L_i(0) * y_i
            lagrange_coeff = _gf_mul(_gf_div(numerator, denominator), y_values[i])
            result ^= lagrange_coeff
        
        secret[byte_idx] = result
    
    return bytes(secret)


# ═══════════════════════════════════════════════════════════════════════════
#  High-Level API for Multi-Carrier Embedding
# ═══════════════════════════════════════════════════════════════════════════

def split_payload_for_carriers(payload: bytes, k: int, n: int) -> List[bytes]:
    """
    Split payload into n share-blobs ready for embedding.
    
    Returns a list of n byte-strings, each containing the full share
    (header + data).  Any k of these can reconstruct the original.
    """
    shares = split_secret(payload, k, n)
    return [share_bytes for _, share_bytes in shares]


def reconstruct_payload_from_shares(share_blobs: List[bytes]) -> bytes:
    """
    Reconstruct payload from extracted share blobs.
    
    Each blob must include the 12-byte SHSS header.
    """
    # Parse share IDs from headers
    shares = []
    for blob in share_blobs:
        if len(blob) < 12:
            continue
        _, _, _, share_id, _, _ = struct.unpack("<4sBBBBI", blob[:12])
        shares.append((share_id, blob))
    
    return reconstruct_secret(shares)
