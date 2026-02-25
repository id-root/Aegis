import pytest
import numpy as np
import os
import cv2
from PIL import Image
from aegis.offensive.algorithms.f5_stego import get_changeable_dct_coeffs, f5_embed_bit, embed_f5_jpeg, extract_f5_jpeg
from aegis.offensive.algorithms.adaptive import get_texture_mask, embed_adaptive, extract_adaptive

# We need some dummy images to test with
@pytest.fixture
def dummy_jpeg(tmp_path):
    # Create a simple non-uniform JPEG
    img_path = str(tmp_path / "test.jpg")
    arr = np.random.randint(0, 255, (256, 256, 3), dtype=np.uint8)
    img = Image.fromarray(arr)
    img.save(img_path, format="JPEG", quality=90)
    return img_path

@pytest.fixture
def dummy_png(tmp_path):
    img_path = str(tmp_path / "test.png")
    # Needs texture for adaptive to work
    arr = np.random.randint(0, 255, (256, 256, 3), dtype=np.uint8)
    img = Image.fromarray(arr)
    img.save(img_path, format="PNG")
    return img_path

def test_f5_roundtrip(dummy_jpeg, tmp_path):
    out_path = str(tmp_path / "stego.jpg")
    payload = b"Test payload for F5 algorithm"
    
    embed_f5_jpeg(dummy_jpeg, out_path, payload)
    
    # Verify file exists and is different (or at least valid)
    assert os.path.exists(out_path)
    
    extracted = extract_f5_jpeg(out_path)
    assert extracted == payload

def test_adaptive_roundtrip(dummy_png, tmp_path):
    out_path = str(tmp_path / "stego.png")
    payload = b"Test payload for Adaptive algorithm"
    
    embed_adaptive(dummy_png, out_path, payload)
    
    assert os.path.exists(out_path)
    
    extracted = extract_adaptive(out_path)
    assert extracted == payload

def test_f5_capacity_error(dummy_jpeg, tmp_path):
    out_path = str(tmp_path / "stego.jpg")
    # 256x256 image won't hold 100kb
    huge_payload = os.urandom(100 * 1024) 
    
    with pytest.raises(ValueError, match="Payload too large"):
         embed_f5_jpeg(dummy_jpeg, out_path, huge_payload)

def test_adaptive_capacity_error(tmp_path):
    # Create an image with ZERO texture (pure black)
    img_path = str(tmp_path / "flat.png")
    arr = np.zeros((256, 256, 3), dtype=np.uint8)
    img = Image.fromarray(arr)
    img.save(img_path, format="PNG")
    
    out_path = str(tmp_path / "stego.png")
    payload = b"Any payload"
    
    # Capacity should be 0
    with pytest.raises(ValueError, match="Payload too large"):
         embed_adaptive(img_path, out_path, payload)
