import os
import io
import tempfile
import numpy as np
from PIL import Image, ImageChops, ImageEnhance, ImageFilter
from typing import Dict, Any, Tuple

def perform_ela(image_path: str, quality: int = 90) -> Tuple[Image.Image, float]:
    """
    Perform Error Level Analysis (ELA).
    1. Saves the image at a known JPEG quality.
    2. Compares the original image to the resaved image.
    3. The absolute difference highlights areas of different compression levels.
    
    Returns the ELA image differential and a scalar value representing the max difference.
    """
    original = Image.open(image_path).convert('RGB')
    
    # Save to a temporary requested JPEG quality
    fd, temp_path = tempfile.mkstemp(suffix=".jpg")
    os.close(fd)
    
    original.save(temp_path, "JPEG", quality=quality)
    resaved = Image.open(temp_path)
    
    # Calculate difference
    ela_image = ImageChops.difference(original, resaved)
    
    # Get extents to normalize brightness of the ELA image
    extrema = ela_image.getextrema()
    max_diff = max([ex[1] for ex in extrema])
    
    if max_diff != 0:
        # Scale to 255
        scale = 255.0 / max_diff
        ela_image = ImageEnhance.Brightness(ela_image).enhance(scale)
        
    os.remove(temp_path)
    return ela_image, float(max_diff)

def analyze_noise_variance(image_path: str) -> Dict[str, Any]:
    """
    Calculates the noise variance over 16x16 pixel blocks.
    A high discrepancy between block noise levels can indicate splicing.
    """
    try:
        img = Image.open(image_path).convert('L')
        # Apply a simple edge/noise detection filter (Laplacian-like)
        # by subtracting the blurred image from the original
        blur = img.filter(ImageFilter.GaussianBlur(radius=1))
        
        arr_img = np.array(img, dtype=np.int16)
        arr_blur = np.array(blur, dtype=np.int16)
        
        noise = arr_img - arr_blur
        
        # Calculate variance on blocks (skip boundaries)
        h, w = noise.shape
        block_size = 16
        variances = []
        
        for y in range(0, h - block_size, block_size):
            for x in range(0, w - block_size, block_size):
                block = noise[y:y+block_size, x:x+block_size]
                variances.append(float(np.var(block)))
                
        if not variances:
            return {"noise_discrepancy": 0.0, "status": "OK"}
            
        std_of_var = float(np.std(variances))
        max_var = max(variances)
        discrepancy_score = (max_var / (np.mean(variances) + 1e-5))
        
        is_suspicious = discrepancy_score > 10.0  # heuristic threshold
        
        return {
            "noise_discrepancy_score": discrepancy_score,
            "variance_std_dev": std_of_var,
            "status": "SUSPICIOUS (Possible Splicing)" if is_suspicious else "OK"
        }
    except Exception as e:
        return {"error": str(e)}

def check_thumbnail_discrepancy(image_path: str) -> Dict[str, Any]:
    """
    Extracts the embedded EXIF thumbnail (if any) and compares its aspect ratio
    to the main image. A significant difference indicates the main image was likely cropped
    without updating the thumbnail.
    """
    try:
        with Image.open(image_path) as img:
            exif_bytes = img.info.get("exif", b"")
            if not exif_bytes:
                return {"has_thumbnail": False}
                
            start = exif_bytes.find(b"\xff\xd8")
            end = exif_bytes.find(b"\xff\xd9", start)
            
            if start != -1 and end != -1:
                thumb_bytes = exif_bytes[start:end+2]
                with Image.open(io.BytesIO(thumb_bytes)) as thumb:
                    main_ar = img.width / max(1, img.height)
                    thumb_ar = thumb.width / max(1, thumb.height)
                    
                    ar_diff = abs(main_ar - thumb_ar)
                    is_suspicious = ar_diff > 0.1
                    
                    return {
                        "has_thumbnail": True,
                        "thumbnail_dimensions": list(thumb.size),
                        "aspect_ratio_diff": float(ar_diff),
                        "status": "SUSPICIOUS (Thumbnail Mismatch)" if is_suspicious else "OK"
                    }
    except Exception:
        pass
    return {"has_thumbnail": False}

def analyze_authenticity(image_path: str) -> Dict[str, Any]:
    """
    Returns a dictionary of authenticity signals.
    """
    result = {}
    try:
        ela_img, max_diff = perform_ela(image_path)
        result["ela_max_difference"] = max_diff
        result["manipulation_confidence"] = (max_diff / 255.0) * 100
        result["status"] = "SUSPICIOUS (ELA)" if max_diff > 50 else "OK"
        
        # Quantization Table (DQT) Extraction
        try:
            with Image.open(image_path) as img:
                if hasattr(img, 'quantization') and img.quantization:
                    dqt_export = {}
                    for key, val in img.quantization.items():
                        # Serialize lists safely
                        dqt_export[str(key)] = list(val)
                    result["quantization_tables"] = dqt_export
                    
                    # Basic heuristic - most standard cameras use standard tables, 
                    # multiple saves or specific software can leave distinct signatures
                    if len(dqt_export) > 0:
                        result["has_custom_dqt"] = True
        except Exception:
            pass
            
        # Noise Variance block analysis
        noise_results = analyze_noise_variance(image_path)
        result["noise_analysis"] = noise_results
        
        # Thumbnail Discrepancy
        thumb_results = check_thumbnail_discrepancy(image_path)
        result["thumbnail_analysis"] = thumb_results
        
        if noise_results.get("status", "").startswith("SUSPICIOUS") or thumb_results.get("status", "").startswith("SUSPICIOUS"):
            result["status"] = "SUSPICIOUS (Multiple Signals Detected)"
            
        return result
    except Exception as e:
        return {"error": str(e)}
