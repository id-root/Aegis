import os
import numpy as np
from PIL import Image
from typing import Dict, Any
import math

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

def analyze_steganography(image_path: str) -> Dict[str, Any]:
    """
    Statistical steganography detection.
    """
    try:
        with Image.open(image_path) as img:
            img = img.convert('RGB')
            entropy_val = calculate_entropy(img)
            
            # Very basic anomaly score.
            # Real steganography detection involves checking LSB distribution.
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
                
            return {
                "entropy": entropy_val,
                "pvd_statistics": pvd_stats,
                "lsb_ratio": {
                    "R": float(lsb_ratio_r),
                    "G": float(lsb_ratio_g),
                    "B": float(lsb_ratio_b)
                },
                "lsb_anomalies": lsb_anomalies,
                "stego_suspicion_score": 100 if len(lsb_anomalies) > 1 else 0
            }
    except Exception as e:
        return {"error": str(e)}
