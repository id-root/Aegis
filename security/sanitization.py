from PIL import Image
from aegis.core.pipeline import OperationRegistry

@OperationRegistry.register("sanitize")
def sanitize_image(image: Image.Image, format: str = "PNG") -> Image.Image:
    """
    Sanitizes an image by stripping all EXIF and metadata.
    By extracting the raw pixel data and creating a new image without the info dictionary.
    """
    # Create a fresh image with the same mode and size
    clean_image = Image.new(image.mode, image.size)
    
    # Put data from old to new
    clean_image.putdata(list(image.getdata()))
    
    return clean_image
