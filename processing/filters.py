from PIL import Image, ImageEnhance, ImageFilter
from typing import Any
import numpy as np
import cv2
from aegis.core.pipeline import OperationRegistry

@OperationRegistry.register("brightness")
def adjust_brightness(image: Image.Image, factor: float) -> Image.Image:
    """Adjust brightness. factor=1.0 is original, >1.0 is brighter, <1.0 is darker."""
    enhancer = ImageEnhance.Brightness(image)
    return enhancer.enhance(factor)

@OperationRegistry.register("contrast")
def adjust_contrast(image: Image.Image, factor: float) -> Image.Image:
    """Adjust contrast. factor=1.0 is original."""
    enhancer = ImageEnhance.Contrast(image)
    return enhancer.enhance(factor)

@OperationRegistry.register("saturation")
def adjust_saturation(image: Image.Image, factor: float) -> Image.Image:
    """Adjust color saturation. factor=1.0 is original."""
    enhancer = ImageEnhance.Color(image)
    return enhancer.enhance(factor)

@OperationRegistry.register("sharpen")
def apply_sharpen(image: Image.Image, radius: int = 2, percent: int = 150) -> Image.Image:
    """Applies an unsharp mask filter."""
    return image.filter(ImageFilter.UnsharpMask(radius=radius, percent=percent))

@OperationRegistry.register("denoise")
def apply_denoise(image: Image.Image, strength: float = 10.0) -> Image.Image:
    """
    Applies Non-Local Means Denoising using OpenCV.
    Requires converting Pillow -> Numpy -> OpenCV -> Pillow.
    """
    # OpenCV requires Numpy arrays
    img_arr = np.array(image)
    
    # Check if RGB or RGBA or Gray
    if len(img_arr.shape) == 3 and img_arr.shape[2] == 3:
        # Convert RGB to BGR for OpenCV
        img_bgr = cv2.cvtColor(img_arr, cv2.COLOR_RGB2BGR)
        denoised_bgr = cv2.fastNlMeansDenoisingColored(img_bgr, None, strength, strength, 7, 21)
        # Convert back to RGB
        denoised_rgb = cv2.cvtColor(denoised_bgr, cv2.COLOR_BGR2RGB)
        return Image.fromarray(denoised_rgb)
    elif len(img_arr.shape) == 2:
        # Grayscale
        denoised_gray = cv2.fastNlMeansDenoising(img_arr, None, strength, 7, 21)
        return Image.fromarray(denoised_gray)
    else:
        # Fallback for RGBA or strange formats: just apply a simple median filter via Pillow
        return image.filter(ImageFilter.MedianFilter(size=3))
