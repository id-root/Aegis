from PIL import Image
from typing import Tuple, Optional
from aegis.core.pipeline import OperationRegistry

@OperationRegistry.register("resize")
def resize_image(image: Image.Image, width: int, height: int) -> Image.Image:
    """Resizes the image to the specified width and height."""
    # Antialiasing is LANCZOS in newer Pillow
    return image.resize((width, height), Image.Resampling.LANCZOS)

@OperationRegistry.register("crop")
def crop_image(image: Image.Image, left: int, top: int, right: int, bottom: int) -> Image.Image:
    """Crops the image based on given coordinates."""
    return image.crop((left, top, right, bottom))

@OperationRegistry.register("convert")
def convert_format(image: Image.Image, mode: str) -> Image.Image:
    """Converts the image to the specified mode (e.g., 'RGB', 'L', 'RGBA')."""
    return image.convert(mode)

@OperationRegistry.register("rotate")
def rotate_image(image: Image.Image, angle: float, expand: bool = True) -> Image.Image:
    """Rotates the image by a given angle in degrees."""
    return image.rotate(angle, expand=expand, resample=Image.Resampling.BICUBIC)
