"""
Spatial-Domain Cost Functions for Adaptive Steganography

Implements three well-studied, deterministic distortion-minimisation cost
functions.  Each function takes an (H, W) or (H, W, C) uint8 image array
and returns an (H, W) float64 cost map where **lower cost = safer to modify**.

Functions
---------
compute_hill_cost  — HILL (High-pass, Low-pass, Low-pass) cascade
compute_wow_cost   — WOW (Wavelet Obtained Weights)
compute_mipod_cost — MiPOD (Minimizing Power of Optimal Detector)

All implementations are pure NumPy — zero ML, fully deterministic.
"""

import numpy as np
from scipy import ndimage, signal


# ── Shared helpers ──────────────────────────────────────────────────────────

def _to_grayscale_float(image_array: np.ndarray) -> np.ndarray:
    """Convert to float64 grayscale if needed."""
    if image_array.ndim == 3:
        # BT.601 luminance
        arr = (0.299 * image_array[:, :, 0] +
               0.587 * image_array[:, :, 1] +
               0.114 * image_array[:, :, 2])
    else:
        arr = image_array.astype(np.float64)
    return arr.astype(np.float64)


def _clamp_cost(cost: np.ndarray, floor: float = 1e-10) -> np.ndarray:
    """Clamp cost away from zero/inf to prevent numerical issues in STC."""
    cost = np.maximum(cost, floor)
    cost[~np.isfinite(cost)] = floor
    return cost


# ── KB filter (3×3 high-pass used in HILL & WOW) ───────────────────────────

_KB_KERNEL = np.array([
    [-1,  2, -1],
    [ 2, -4,  2],
    [-1,  2, -1]
], dtype=np.float64)


# ═══════════════════════════════════════════════════════════════════════════
#  HILL  —  High-pass  →  Low-pass  →  Low-pass
# ═══════════════════════════════════════════════════════════════════════════

def compute_hill_cost(image_array: np.ndarray) -> np.ndarray:
    """
    HILL (Li et al., 2014) distortion cost.

    Pipeline:
        1. High-pass residual  R = |image ⊛ KB|     (3×3 Laplacian-like)
        2. Low-pass 1          L1 = R ⊛ avg(3×3)    (local smoothing)
        3. Low-pass 2          L2 = L1 ⊛ avg(15×15) (large-scale averaging)
        4. Cost  ρ = 1 / (L2 + ε)

    Returns
    -------
    np.ndarray, shape (H, W), float64  — per-pixel embedding cost.
    """
    gray = _to_grayscale_float(image_array)

    # Step 1 — high-pass residual
    residual = np.abs(ndimage.convolve(gray, _KB_KERNEL, mode='reflect'))

    # Step 2 — local low-pass (3×3 mean)
    lp1_kernel = np.ones((3, 3), dtype=np.float64) / 9.0
    lp1 = ndimage.convolve(residual, lp1_kernel, mode='reflect')

    # Step 3 — broad low-pass (15×15 mean)
    lp2_kernel = np.ones((15, 15), dtype=np.float64) / 225.0
    lp2 = ndimage.convolve(lp1, lp2_kernel, mode='reflect')

    # Step 4 — cost is reciprocal
    cost = 1.0 / (lp2 + 1e-10)

    return _clamp_cost(cost)


# ═══════════════════════════════════════════════════════════════════════════
#  WOW  —  Wavelet Obtained Weights
# ═══════════════════════════════════════════════════════════════════════════

def compute_wow_cost(image_array: np.ndarray) -> np.ndarray:
    """
    WOW (Holub & Fridrich, 2012) distortion cost.

    Uses Haar wavelet decomposition at 3 scales.  At each scale the
    directional prediction residuals (LH, HL, HH) are computed and their
    reciprocals are aggregated to form the final cost.

    Returns
    -------
    np.ndarray, shape (H, W), float64  — per-pixel embedding cost.
    """
    gray = _to_grayscale_float(image_array)
    h, w = gray.shape

    # Haar filter bank (1-D)
    lo = np.array([1.0, 1.0]) / np.sqrt(2)
    hi = np.array([1.0, -1.0]) / np.sqrt(2)

    # Pad to even dimensions
    pad_h = h + (h % 2)
    pad_w = w + (w % 2)
    padded = np.zeros((pad_h, pad_w), dtype=np.float64)
    padded[:h, :w] = gray

    combined = np.zeros((h, w), dtype=np.float64)

    current = padded.copy()
    for scale in range(3):
        ch, cw = current.shape

        # Row filtering
        rows_lo = np.zeros((ch, cw // 2), dtype=np.float64)
        rows_hi = np.zeros((ch, cw // 2), dtype=np.float64)
        for r in range(ch):
            full_lo = np.convolve(current[r, :], lo, mode='full')[:cw]
            full_hi = np.convolve(current[r, :], hi, mode='full')[:cw]
            rows_lo[r, :] = full_lo[::2][:cw // 2]
            rows_hi[r, :] = full_hi[::2][:cw // 2]

        half_w = cw // 2
        half_h = ch // 2

        # Column filtering on each row-filtered output
        ll = np.zeros((half_h, half_w), dtype=np.float64)
        lh = np.zeros((half_h, half_w), dtype=np.float64)
        hl = np.zeros((half_h, half_w), dtype=np.float64)
        hh = np.zeros((half_h, half_w), dtype=np.float64)

        for c in range(half_w):
            col_lo_lo = np.convolve(rows_lo[:, c], lo, mode='full')[:ch]
            col_lo_hi = np.convolve(rows_lo[:, c], hi, mode='full')[:ch]
            col_hi_lo = np.convolve(rows_hi[:, c], lo, mode='full')[:ch]
            col_hi_hi = np.convolve(rows_hi[:, c], hi, mode='full')[:ch]

            ll[:, c] = col_lo_lo[::2][:half_h]
            lh[:, c] = col_lo_hi[::2][:half_h]
            hl[:, c] = col_hi_lo[::2][:half_h]
            hh[:, c] = col_hi_hi[::2][:half_h]

        # Directional costs at this scale — upsample to full size
        for subband in [lh, hl, hh]:
            # Reciprocal of absolute subband values
            xi = 1.0 / (np.abs(subband) + 1e-10)
            # Resize to original image dimensions
            from PIL import Image as _PILImage
            xi_img = _PILImage.fromarray(xi)
            xi_up = np.array(xi_img.resize((w, h), _PILImage.Resampling.BILINEAR))
            combined += xi_up

        # Next scale operates on the LL subband
        current = ll

    return _clamp_cost(combined)


# ═══════════════════════════════════════════════════════════════════════════
#  MiPOD  —  Minimizing the Power of Optimal Detector
# ═══════════════════════════════════════════════════════════════════════════

def compute_mipod_cost(image_array: np.ndarray) -> np.ndarray:
    """
    MiPOD (Sedighi et al., 2016) approximation.

    Estimates the pixel-wise variance of the cover-image acquisition noise
    model using local neighbourhood statistics.  The cost is set such that
    modifications in high-variance regions contribute minimally to the KL
    divergence between cover and stego distributions.

    Simplified closed-form (no iterative ML fitting):
        σ²_i  ≈  local_variance(neighbourhood)
        ρ_i   ∝  σ²_i   (higher variance → cheaper to modify)
        cost  =  1 / ρ_i = 1 / σ²_i

    Returns
    -------
    np.ndarray, shape (H, W), float64  — per-pixel embedding cost.
    """
    gray = _to_grayscale_float(image_array)

    # Estimate local variance using multiple filter residuals
    # Residual from 3×3 Wiener-like predictor
    local_mean = ndimage.uniform_filter(gray, size=5)
    local_sq_mean = ndimage.uniform_filter(gray ** 2, size=5)
    local_var = np.maximum(local_sq_mean - local_mean ** 2, 0.0)

    # Also get high-pass residual variance for robustness
    hp_residual = ndimage.convolve(gray, _KB_KERNEL, mode='reflect')
    hp_var = ndimage.uniform_filter(hp_residual ** 2, size=5)

    # Combined variance estimate
    sigma_sq = 0.5 * local_var + 0.5 * hp_var

    # Cost is inverse of variance (high variance = low cost = safe to embed)
    cost = 1.0 / (sigma_sq + 1e-10)

    return _clamp_cost(cost)


# ═══════════════════════════════════════════════════════════════════════════
#  Public API  —  unified dispatcher
# ═══════════════════════════════════════════════════════════════════════════

COST_FUNCTIONS = {
    "hill": compute_hill_cost,
    "wow": compute_wow_cost,
    "mipod": compute_mipod_cost,
}


def get_cost_map(image_array: np.ndarray, method: str = "hill") -> np.ndarray:
    """
    Compute the embedding cost map using the specified method.

    Parameters
    ----------
    image_array : np.ndarray
        (H, W) or (H, W, C) uint8 image.
    method : str
        One of 'hill', 'wow', 'mipod'.

    Returns
    -------
    np.ndarray, shape (H, W), float64
    """
    method = method.lower()
    if method not in COST_FUNCTIONS:
        raise ValueError(f"Unknown cost function '{method}'. Choose from: {list(COST_FUNCTIONS.keys())}")
    return COST_FUNCTIONS[method](image_array)
