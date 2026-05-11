"""
Steganography Detection & Analysis Module

Provides multiple statistical steganalysis attacks:
  1. Shannon Entropy — measures information density
  2. LSB Distribution Analysis — checks for unnatural LSB uniformity
  3. Pixel Value Differencing (PVD) — horizontal pixel difference statistics
  4. Chi-Square Attack (χ²) — Pairs-of-Values analysis detecting sequential
     LSB replacement by measuring the equalisation of PoV pairs
  5. RS Analysis — Regular/Singular group classification to detect LSB
     matching/embedding by comparing flipping discriminant functions
  6. Bit-Plane Extraction — visual separation of each binary bit-plane
"""

import os
import numpy as np
from PIL import Image
from typing import Dict, Any, List
import math

# ---------------------------------------------------------------------------
# Core Statistics
# ---------------------------------------------------------------------------

def calculate_entropy(image: Image.Image) -> float:
    """
    Calculate Shannon entropy of the image.
    High entropy (close to 8) indicates highly compressed or encrypted data,
    which is a potential sign of steganography if the visual image is simple.
    """
    histogram = image.histogram()
    histogram_length = sum(histogram)
    
    samples_probability = [float(h) / histogram_length for h in histogram if h > 0]
    entropy = -sum([p * math.log(p, 2) for p in samples_probability])
    return entropy

def calculate_pvd_stats(image: Image.Image) -> Dict[str, float]:
    """
    Pixel Value Differencing (PVD) statistics.
    Analyzes the horizontal differences of grayscale pixels.
    """
    arr = np.array(image.convert('L'), dtype=np.int16)
    diffs = np.diff(arr, axis=1)
    
    mean_diff = float(np.mean(np.abs(diffs)))
    var_diff = float(np.var(diffs))
    
    return {
        "mean_absolute_difference": mean_diff,
        "difference_variance": var_diff
    }


# ---------------------------------------------------------------------------
# Chi-Square Attack  (Pairs of Values / PoV)
# ---------------------------------------------------------------------------

def chi_square_attack(image: Image.Image, block_size: int = 128) -> Dict[str, Any]:
    """
    Chi-Square (χ²) steganalysis attack.

    Detects sequential LSB replacement steganography by exploiting the
    Pairs-of-Values (PoV) phenomenon:  LSB embedding causes adjacent
    histogram bins (2i, 2i+1) to converge towards equal frequencies.

    The test computes a χ² statistic over histogram pairs and converts
    it to a p-value.  A p-value close to 1.0 strongly indicates the
    presence of LSB steganography.

    The analysis is performed on sliding blocks along the image width
    to produce a spatial embedding-probability profile.

    Returns
    -------
    dict with:
      - overall_p_value : float  — global χ² p-value (0–1, higher = more suspicious)
      - block_p_values  : list   — per-block p-values for spatial profiling
      - status          : str    — human-readable verdict
    """
    arr = np.array(image.convert("L"), dtype=np.uint8)
    h, w = arr.shape

    def _chi_sq_pvalue(data_block: np.ndarray) -> float:
        """Compute χ² p-value for a single pixel block."""
        hist = np.bincount(data_block.flatten(), minlength=256).astype(np.float64)

        chi2 = 0.0
        degrees = 0
        for i in range(0, 256, 2):
            pair_sum = hist[i] + hist[i + 1]
            if pair_sum > 0:
                expected = pair_sum / 2.0
                chi2 += ((hist[i] - expected) ** 2) / expected
                chi2 += ((hist[i + 1] - expected) ** 2) / expected
                degrees += 1

        if degrees == 0:
            return 0.0

        # Approximate p-value via the regularised incomplete gamma function
        # For large degrees of freedom, we use the Wilson-Hilferty normal
        # approximation to the χ² CDF:
        #   Z ≈ ( (χ²/ν)^(1/3) - (1 - 2/(9ν)) ) / sqrt(2/(9ν))
        # p ≈ Φ(Z)  where Φ is the standard normal CDF
        nu = float(degrees)
        if nu == 0:
            return 0.0
        z_num = (chi2 / nu) ** (1.0 / 3.0) - (1.0 - 2.0 / (9.0 * nu))
        z_den = math.sqrt(2.0 / (9.0 * nu))
        if z_den == 0:
            return 0.0
        z = z_num / z_den

        # Standard normal CDF approximation (Abramowitz & Stegun 7.1.26)
        p_value = 0.5 * (1.0 + math.erf(-z / math.sqrt(2.0)))

        return float(np.clip(p_value, 0.0, 1.0))

    # Overall p-value
    overall_p = _chi_sq_pvalue(arr)

    # Block-wise profile (horizontal blocks)
    block_pvals: List[float] = []
    for x_start in range(0, w, block_size):
        x_end = min(x_start + block_size, w)
        block_data = arr[:, x_start:x_end]
        if block_data.size > 0:
            block_pvals.append(_chi_sq_pvalue(block_data))

    # Verdict
    if overall_p > 0.95:
        status = "HIGHLY SUSPICIOUS (χ² PoV attack: strong LSB embedding signal)"
    elif overall_p > 0.80:
        status = "SUSPICIOUS (χ² PoV attack: moderate LSB embedding signal)"
    elif overall_p > 0.50:
        status = "UNCERTAIN (χ² PoV attack: weak signal, inconclusive)"
    else:
        status = "CLEAN (χ² PoV attack: no significant LSB embedding detected)"

    return {
        "overall_p_value": round(overall_p, 6),
        "block_p_values": [round(p, 4) for p in block_pvals],
        "num_blocks_suspicious": sum(1 for p in block_pvals if p > 0.90),
        "status": status,
    }


# ---------------------------------------------------------------------------
# RS Analysis  (Regular / Singular groups)
# ---------------------------------------------------------------------------

def rs_analysis(image: Image.Image, group_size: int = 4) -> Dict[str, Any]:
    """
    RS (Regular/Singular) Steganalysis.

    Classifies pixel groups as Regular (R), Singular (S), or Unusable (U)
    under positive and negative flipping functions.  In a clean image,
    R_m ≈ R_{-m} and S_m ≈ S_{-m}.  LSB embedding causes a characteristic
    divergence:  R_m increases and S_m decreases relative to their negative
    counterparts.

    The *estimated embedding rate* is derived from the RS statistics using the
    quadratic formula from Fridrich et al. (2001).

    Returns
    -------
    dict with:
      - r_positive, s_positive : float — R/S ratios under positive mask
      - r_negative, s_negative : float — R/S ratios under negative mask
      - estimated_embedding_rate : float — estimated fraction of pixels with
        embedded data (0.0 = clean, 0.5 = fully embedded)
      - status : str
    """
    arr = np.array(image.convert("L"), dtype=np.int16)
    h, w = arr.shape

    def _discrimination_fn(group: np.ndarray) -> float:
        """Sum of absolute differences between adjacent pixels in the group."""
        return float(np.sum(np.abs(np.diff(group))))

    def _flip_positive(val: int) -> int:
        """F1: flip LSB (0↔1, 2↔3, 4↔5, …)."""
        return val ^ 1

    def _flip_negative(val: int) -> int:
        """F_{-1}: flip with shift (0↔-1 mapped to 0↔255, 2↔1, 4↔3, …).
        Equivalent to  -(val+1) in the mod-256 sense, i.e. val ^ 1 then
        swap 2k↔2k+1 in the opposite direction."""
        if val % 2 == 0:
            return val - 1 if val > 0 else 255
        else:
            return val + 1 if val < 255 else 0

    # Mask pattern:  [1, 0, 1, 0, …]  applied to groups of `group_size`
    mask = np.array([i % 2 for i in range(group_size)])

    r_pos = 0  # regular groups under positive flip
    s_pos = 0  # singular groups under positive flip
    r_neg = 0  # regular groups under negative flip
    s_neg = 0  # singular groups under negative flip
    total_groups = 0

    # Process the image row by row, group by group
    for row_idx in range(h):
        row = arr[row_idx, :]
        for col_start in range(0, w - group_size + 1, group_size):
            group = row[col_start: col_start + group_size].copy()
            total_groups += 1

            f_original = _discrimination_fn(group)

            # Positive flipping
            g_pos = group.copy()
            for j in range(group_size):
                if mask[j]:
                    g_pos[j] = _flip_positive(int(g_pos[j]) & 0xFF)
            f_pos = _discrimination_fn(g_pos)

            if f_pos > f_original:
                r_pos += 1
            elif f_pos < f_original:
                s_pos += 1

            # Negative flipping
            g_neg = group.copy()
            for j in range(group_size):
                if mask[j]:
                    g_neg[j] = _flip_negative(int(g_neg[j]) & 0xFF)
            f_neg = _discrimination_fn(g_neg)

            if f_neg > f_original:
                r_neg += 1
            elif f_neg < f_original:
                s_neg += 1

    if total_groups == 0:
        return {
            "r_positive": 0.0, "s_positive": 0.0,
            "r_negative": 0.0, "s_negative": 0.0,
            "estimated_embedding_rate": 0.0,
            "status": "ERROR (no groups)"
        }

    # Normalise to ratios
    rp = r_pos / total_groups
    sp = s_pos / total_groups
    rn = r_neg / total_groups
    sn = s_neg / total_groups

    # Estimate embedding rate via quadratic formula (Fridrich et al. 2001)
    # The equation is:  2(d1 + d0) * p^2  +  (d_{-1} - d_{-0} - d1 - 3*d0) * p  +  (d0 - d_{-0}) = 0
    # where  d1 = Rm - Sm,  d0 = R0 - S0  (at embedding rate 0 — approximated),
    # d_{-1} = R_{-m} - S_{-m}
    # Simplified approximation:
    d1 = rp - sp
    d_neg1 = rn - sn

    # Approximate embedding rate
    if abs(d1) < 1e-10:
        est_rate = 0.0
    else:
        # Linear approximation: p ≈ (d1 - d_{-1}) / (2 * d1)
        est_rate = (d1 - d_neg1) / (2.0 * d1)
        est_rate = float(np.clip(est_rate, 0.0, 0.5))

    # Verdict
    if est_rate > 0.10:
        status = "SUSPICIOUS (RS analysis: significant LSB embedding detected)"
    elif est_rate > 0.03:
        status = "UNCERTAIN (RS analysis: possible low-rate embedding)"
    else:
        status = "CLEAN (RS analysis: no significant embedding detected)"

    return {
        "r_positive": round(rp, 6),
        "s_positive": round(sp, 6),
        "r_negative": round(rn, 6),
        "s_negative": round(sn, 6),
        "estimated_embedding_rate": round(est_rate, 6),
        "status": status,
    }


# ---------------------------------------------------------------------------
# Bit-Plane Extraction
# ---------------------------------------------------------------------------

def generate_bitplanes(image_path: str, output_dir: str):
    """
    Extracts the 8 bit-planes of the image (grayscale) and saves them
    as separate PNG files in the specified directory.
    """
    os.makedirs(output_dir, exist_ok=True)
    with Image.open(image_path) as img:
        arr = np.array(img.convert('L'))
        for i in range(8):
            plane = (arr >> i) & 1
            plane_img = Image.fromarray((plane * 255).astype(np.uint8))
            out_file = os.path.join(output_dir, f"bitplane_{i}.png")
            plane_img.save(out_file)
    return True


# ---------------------------------------------------------------------------
# Unified Analysis Entry Point
# ---------------------------------------------------------------------------

def analyze_steganography(image_path: str) -> Dict[str, Any]:
    """
    Comprehensive statistical steganography detection.
    
    Combines multiple detection methods:
      - Shannon entropy
      - LSB distribution ratio per channel
      - Pixel Value Differencing (PVD)
      - Chi-Square (χ²) Pairs-of-Values attack
      - RS (Regular/Singular) analysis
    """
    try:
        with Image.open(image_path) as img:
            img = img.convert('RGB')
            entropy_val = calculate_entropy(img)
            
            array = np.array(img)
            # Check the least significant bit randomness
            lsb_r = array[:,:,0] & 1
            lsb_g = array[:,:,1] & 1
            lsb_b = array[:,:,2] & 1
            
            lsb_ratio_r = np.sum(lsb_r) / lsb_r.size
            lsb_ratio_g = np.sum(lsb_g) / lsb_g.size
            lsb_ratio_b = np.sum(lsb_b) / lsb_b.size
            
            # An ideal random distribution of LSBs has a ratio near 0.5.
            lsb_anomalies = []
            if abs(lsb_ratio_r - 0.5) > 0.05: lsb_anomalies.append("R_CHANNEL_BIAS")
            if abs(lsb_ratio_g - 0.5) > 0.05: lsb_anomalies.append("G_CHANNEL_BIAS")
            if abs(lsb_ratio_b - 0.5) > 0.05: lsb_anomalies.append("B_CHANNEL_BIAS")
            
            # PVD Stats
            pvd_stats = calculate_pvd_stats(img)
            
            # Chi-Square Attack
            chi_sq_results = chi_square_attack(img)
            
            # RS Analysis
            rs_results = rs_analysis(img)
            
            # ----- Composite Suspicion Score -----
            # Weight multiple signals into a 0-100 score.
            score = 0.0
            
            # LSB anomalies (old heuristic, lower weight)
            if len(lsb_anomalies) > 1:
                score += 15.0
            elif len(lsb_anomalies) == 1:
                score += 5.0
            
            # Chi-Square p-value is the strongest indicator for LSB replacement
            chi_p = chi_sq_results.get("overall_p_value", 0.0)
            if chi_p > 0.95:
                score += 45.0
            elif chi_p > 0.80:
                score += 30.0
            elif chi_p > 0.50:
                score += 10.0
            
            # RS embedding rate
            rs_rate = rs_results.get("estimated_embedding_rate", 0.0)
            if rs_rate > 0.10:
                score += 40.0
            elif rs_rate > 0.03:
                score += 15.0
            elif rs_rate > 0.01:
                score += 5.0

            score = min(score, 100.0)
                
            return {
                "entropy": entropy_val,
                "pvd_statistics": pvd_stats,
                "lsb_ratio": {
                    "R": float(lsb_ratio_r),
                    "G": float(lsb_ratio_g),
                    "B": float(lsb_ratio_b)
                },
                "lsb_anomalies": lsb_anomalies,
                "chi_square_attack": chi_sq_results,
                "rs_analysis": rs_results,
                "stego_suspicion_score": int(score)
            }
    except Exception as e:
        return {"error": str(e)}
