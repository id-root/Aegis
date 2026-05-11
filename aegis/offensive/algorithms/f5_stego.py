"""
F5 Steganography Algorithm — Full Implementation

Implements the complete F5 algorithm as described by Westfeld (2001):
  1. Permutative Straddling — PRNG-seeded coefficient permutation for uniform
     modification distribution across the carrier image.
  2. (1, n, k) Matrix Encoding — Hamming-code syndrome-based embedding that
     encodes k message bits into a group of n = 2^k - 1 coefficients by
     modifying at most ONE coefficient per group.
  3. Shrinkage Handling — When a coefficient is decremented/incremented to zero,
     the group is rescanned from the same starting position. The zero coefficient
     is naturally skipped, ensuring embedder and extractor stay synchronised.

Security properties:
  - The PRNG seed is derived from the encryption password via SHA-256, binding
    the coefficient permutation to the same secret used for payload encryption.
  - Matrix encoding minimises the number of coefficient changes, preserving
    the carrier's DCT histogram and resisting chi-square / HCF-COM attacks.
"""

import numpy as np
import jpegio as jio
import hashlib
import struct
from typing import List, Tuple

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _derive_prng_seed(password: str) -> int:
    """Derive a deterministic 64-bit PRNG seed from the password."""
    digest = hashlib.sha256(password.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "little")


def _collect_all_ac_positions(coef_arrays: list) -> List[Tuple[int, int, int, int]]:
    """
    Collect ALL AC DCT coefficient positions across every channel.
    Returns a list of (channel_idx, block_y, block_x, coeff_idx) tuples.
    DC coefficients (index 0) are excluded but zero-valued AC coefficients
    ARE included — they will be skipped during group collection.

    This ensures the permuted position list is identical during embedding
    and extraction, even when shrinkage causes some coefficients to become
    zero during embedding.
    """
    positions = []
    for c_idx, channel_dct in enumerate(coef_arrays):
        h, w = channel_dct.shape
        for y in range(0, h, 8):
            for x in range(0, w, 8):
                for i in range(1, 64):  # skip DC (index 0)
                    positions.append((c_idx, y, x, i))
    return positions


def _permute_indices(indices: list, seed: int) -> list:
    """Pseudo-random permutation of the index list (Fisher-Yates via NumPy)."""
    rng = np.random.RandomState(seed & 0xFFFFFFFF)
    order = rng.permutation(len(indices))
    return [indices[o] for o in order]


def _select_k(capacity_coeffs: int, message_bits: int) -> int:
    """
    Choose the optimal matrix-encoding parameter k.

    In (1, n, k) encoding we embed k bits per group of n = 2^k - 1 coefficients
    with at most 1 change.  The embedding rate is k / n message bits per coeff.

    We want the largest k such that we still have enough coefficients:
        ceil(message_bits / k) * n  <=  capacity_coeffs  (with shrinkage margin)

    k is clamped to [1, 7] — higher values create impractically large groups
    (n=8191 for k=13) where a single shrinkage event wastes thousands of
    coefficients.  k ∈ [1,7] gives n ∈ [1,127] which is the practical range
    used in real F5 implementations.
    """
    best_k = 1
    for k in range(1, 8):  # k max = 7 → n max = 127
        n = (1 << k) - 1  # 2^k - 1
        groups_needed = (message_bits + k - 1) // k
        # Shrinkage overhead: conservatively budget 2x for safety
        coeffs_needed = groups_needed * n * 2
        if coeffs_needed <= capacity_coeffs:
            best_k = k
    return best_k


# ---------------------------------------------------------------------------
# Coefficient reading helpers
# ---------------------------------------------------------------------------

def _read_coeff(coef_arrays: list, loc: tuple) -> int:
    """Read the DCT coefficient at the given location."""
    c_idx, y, x, i = loc
    return int(coef_arrays[c_idx][y:y + 8, x:x + 8].flatten()[i])


def _collect_nonzero_group(coef_arrays: list, permuted: list,
                           start: int, count: int) -> Tuple[list, int]:
    """
    Collect `count` non-zero coefficient locations starting from `start`.
    Returns (group_locs, next_ptr) where next_ptr is the position after
    the last scanned index.
    """
    group = []
    ptr = start
    while len(group) < count and ptr < len(permuted):
        loc = permuted[ptr]
        if _read_coeff(coef_arrays, loc) != 0:
            group.append(loc)
        ptr += 1
    return group, ptr


# ---------------------------------------------------------------------------
# Matrix Encoding  –  (1, n, k) Hamming syndrome
# ---------------------------------------------------------------------------

def _syndrome_hash(lsb_group: np.ndarray, k: int) -> int:
    """
    Compute the k-bit syndrome of a group of n = 2^k - 1 LSBs.

    H  =  XOR of  (i)  for every position i (1-indexed) where lsb_group[i-1] == 1

    The result is a k-bit integer in [0, n].
    """
    h = 0
    for i in range(1, len(lsb_group) + 1):
        if lsb_group[i - 1]:
            h ^= i
    return h


def _f5_modify_coeff(coef_arrays: list, loc: tuple) -> bool:
    """
    Decrement the absolute value of the coefficient at *loc* by 1
    (towards zero), as per F5 encoding convention.

    Returns True if the coefficient shrank to zero (shrinkage event).
    """
    c_idx, y, x, i = loc
    block = coef_arrays[c_idx][y:y + 8, x:x + 8]
    flat = block.flatten()
    val = flat[i]

    if val > 0:
        new_val = val - 1
    else:
        new_val = val + 1

    flat[i] = new_val
    coef_arrays[c_idx][y:y + 8, x:x + 8] = flat.reshape((8, 8))

    return new_val == 0


# ---------------------------------------------------------------------------
# Embed
# ---------------------------------------------------------------------------

def embed_f5_jpeg(image_path: str, output_path: str, payload: bytes,
                  password: str = "") -> None:
    """
    Full F5 embedding with permutative straddling and (1,n,k) matrix encoding.

    Parameters
    ----------
    image_path : str
        Path to the cover JPEG.
    output_path : str
        Destination path for the stego JPEG.
    payload : bytes
        The raw ciphertext to embed (already encrypted by the crypto layer).
    password : str
        Used solely to seed the PRNG for coefficient permutation.
    """
    try:
        jpeg = jio.read(image_path)
    except Exception as e:
        raise ValueError(f"Could not read JPEG for steganography: {e}")

    # 1. Collect ALL AC coefficient positions (including zeros for consistent permutation)
    all_positions = _collect_all_ac_positions(jpeg.coef_arrays)

    # 2. Permutative straddling — password-seeded shuffle
    seed = _derive_prng_seed(password)
    permuted = _permute_indices(all_positions, seed)

    # 3. Prepare the bit-stream:  [32-bit little-endian length] + [payload]
    length_bytes = struct.pack("<I", len(payload))
    full_payload = length_bytes + payload
    msg_bits = np.unpackbits(np.frombuffer(full_payload, dtype=np.uint8))
    total_msg_bits = len(msg_bits)

    # Count non-zero coefficients for capacity estimation
    nonzero_count = sum(1 for loc in permuted if _read_coeff(jpeg.coef_arrays, loc) != 0)

    # 4. Choose k for matrix encoding
    k = _select_k(nonzero_count, total_msg_bits)
    n = (1 << k) - 1  # group size

    if total_msg_bits > nonzero_count * k // n:
        raise ValueError(
            f"Payload too large. Capacity ≈ {nonzero_count * k // n} msg-bits, "
            f"Required: {total_msg_bits}"
        )

    # 5. Embed k as a 4-bit header using simple LSB encoding (k ∈ [1,7])
    coeff_ptr = 0
    k_bits = [(k >> b) & 1 for b in range(4)]

    for target_bit in k_bits:
        while coeff_ptr < len(permuted):
            loc = permuted[coeff_ptr]
            val = _read_coeff(jpeg.coef_arrays, loc)
            if val != 0:
                current_lsb = abs(val) & 1
                if current_lsb != target_bit:
                    shrank = _f5_modify_coeff(jpeg.coef_arrays, loc)
                    if shrank:
                        # Coefficient became zero — skip it and retry
                        coeff_ptr += 1
                        continue
                coeff_ptr += 1
                break
            coeff_ptr += 1
        else:
            raise ValueError("Ran out of coefficients during header embedding.")

    # 6. Embed the message using (1, n, k) matrix encoding
    #
    # CRITICAL SYNC RULE: On shrinkage, do NOT advance coeff_ptr.
    # Rescan from the same position — the shrunken coefficient is now zero
    # and will be naturally skipped by both the embedder's retry AND the
    # extractor.  This keeps both sides perfectly synchronised.

    msg_idx = 0
    max_retries = nonzero_count  # prevent infinite loop in degenerate cases

    while msg_idx < total_msg_bits:
        max_retries -= 1
        if max_retries < 0:
            raise ValueError(
                f"Hit capacity limit. Embedded {msg_idx}/{total_msg_bits} bits."
            )

        # Collect n non-zero coefficients from current position
        group_locs, next_ptr = _collect_nonzero_group(
            jpeg.coef_arrays, permuted, coeff_ptr, n
        )

        if len(group_locs) < n:
            raise ValueError(
                f"Hit capacity limit. Embedded {msg_idx}/{total_msg_bits} bits."
            )

        # Read the current LSBs of this group
        group_lsbs = np.array(
            [abs(_read_coeff(jpeg.coef_arrays, loc)) & 1 for loc in group_locs],
            dtype=np.uint8
        )

        # Extract up to k message bits (pad tail with 0)
        bits_available = min(k, total_msg_bits - msg_idx)
        m = 0
        for bi in range(bits_available):
            m |= int(msg_bits[msg_idx + bi]) << bi

        # Compute syndrome
        h = _syndrome_hash(group_lsbs, k)
        s = h ^ m

        if s == 0:
            # No change needed — LSBs already encode the message
            coeff_ptr = next_ptr
            msg_idx += bits_available
        else:
            # s is the 1-indexed position to modify
            target_loc = group_locs[s - 1]
            shrank = _f5_modify_coeff(jpeg.coef_arrays, target_loc)

            if shrank:
                # SHRINKAGE: Do NOT advance coeff_ptr.
                # The shrunken coefficient is now zero. On rescan from the
                # same coeff_ptr, it will be skipped and we'll get a new
                # (slightly shifted) group. The extractor will build the
                # same group because it also skips zeros.
                continue
            else:
                # Successful modification
                coeff_ptr = next_ptr
                msg_idx += bits_available

    # 7. Write output
    try:
        jio.write(jpeg, output_path)
    except Exception as e:
        raise ValueError(f"Failed to write F5 stego JPEG: {e}")


# ---------------------------------------------------------------------------
# Extract
# ---------------------------------------------------------------------------

def extract_f5_jpeg(image_path: str, password: str = "") -> bytes:
    """
    Extract a payload from an F5-embedded JPEG.

    Parameters
    ----------
    image_path : str
        Path to the stego JPEG.
    password : str
        The same password used during embedding (for PRNG permutation).
    """
    try:
        jpeg = jio.read(image_path)
    except Exception as e:
        raise ValueError(f"Could not read JPEG for extraction: {e}")

    # 1. Collect ALL AC positions (same as embedding)
    all_positions = _collect_all_ac_positions(jpeg.coef_arrays)

    # 2. Permute with the same seed
    seed = _derive_prng_seed(password)
    permuted = _permute_indices(all_positions, seed)

    if len(permuted) < 4:
        return b""

    # 3. Read k from the first 4 non-zero coefficients (simple LSB)
    coeff_ptr = 0
    k = 0
    bits_read = 0
    while bits_read < 4 and coeff_ptr < len(permuted):
        loc = permuted[coeff_ptr]
        val = _read_coeff(jpeg.coef_arrays, loc)
        if val != 0:
            bit = abs(val) & 1
            k |= bit << bits_read
            bits_read += 1
        coeff_ptr += 1

    if k < 1 or k > 7:
        return b""

    n = (1 << k) - 1

    # 4. Extract message bits using matrix decoding
    extracted_bits: List[int] = []
    payload_len = None
    total_bits_needed = 32  # start with the length header

    while len(extracted_bits) < total_bits_needed:
        # Collect n non-zero coefficients
        group_locs, next_ptr = _collect_nonzero_group(
            jpeg.coef_arrays, permuted, coeff_ptr, n
        )

        if len(group_locs) < n:
            break  # out of coefficients

        coeff_ptr = next_ptr

        # Read LSBs
        group_lsbs = np.array(
            [abs(_read_coeff(jpeg.coef_arrays, loc)) & 1 for loc in group_locs],
            dtype=np.uint8
        )

        # Compute syndrome = the embedded k-bit value
        h = _syndrome_hash(group_lsbs, k)

        # Unpack the k bits
        for bi in range(k):
            extracted_bits.append((h >> bi) & 1)

        # Once we have 32 bits, decode the payload length
        if payload_len is None and len(extracted_bits) >= 32:
            length_bits_arr = np.array(extracted_bits[:32], dtype=np.uint8)
            length_bytes = np.packbits(length_bits_arr).tobytes()
            payload_len = struct.unpack("<I", length_bytes)[0]

            if payload_len > 10 * 1024 * 1024:  # sanity cap: 10 MB
                return b""

            total_bits_needed = 32 + (payload_len * 8)

    if payload_len is None:
        return b""

    needed = 32 + payload_len * 8
    if len(extracted_bits) < needed:
        return b""

    # Pack only the exact bits we need
    all_bits = np.array(extracted_bits[:needed], dtype=np.uint8)
    all_bytes = np.packbits(all_bits).tobytes()

    return all_bytes[4: 4 + payload_len]
