import pytest
import numpy as np
import os
import cv2
from PIL import Image
from aegis.offensive.algorithms.f5_stego import embed_f5_jpeg, extract_f5_jpeg
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
    password = "test_password_123"
    
    embed_f5_jpeg(dummy_jpeg, out_path, payload, password=password)
    
    # Verify file exists and is different (or at least valid)
    assert os.path.exists(out_path)
    
    extracted = extract_f5_jpeg(out_path, password=password)
    assert extracted == payload

def test_f5_wrong_password(dummy_jpeg, tmp_path):
    """Extracting with the wrong password should yield garbage (not the original payload)."""
    out_path = str(tmp_path / "stego.jpg")
    payload = b"Secret message for F5"
    password = "correct_password"
    wrong_password = "wrong_password"
    
    embed_f5_jpeg(dummy_jpeg, out_path, payload, password=password)
    
    extracted = extract_f5_jpeg(out_path, password=wrong_password)
    # With a wrong PRNG permutation, the extraction should not recover the payload
    assert extracted != payload

def test_f5_matrix_encoding_efficiency(dummy_jpeg, tmp_path):
    """Verify that matrix encoding produces fewer coefficient changes than payload bits."""
    import jpegio as jio
    
    out_path = str(tmp_path / "stego.jpg")
    payload = b"Matrix encoding test payload"
    password = "matrix_test"
    
    # Read original coefficients
    jpeg_orig = jio.read(dummy_jpeg)
    orig_coeffs = [arr.copy() for arr in jpeg_orig.coef_arrays]
    
    embed_f5_jpeg(dummy_jpeg, out_path, payload, password=password)
    
    # Read modified coefficients
    jpeg_stego = jio.read(out_path)
    
    # Count changes
    total_changes = 0
    for c_idx in range(len(orig_coeffs)):
        total_changes += int(np.sum(orig_coeffs[c_idx] != jpeg_stego.coef_arrays[c_idx]))
    
    total_payload_bits = (len(payload) + 4) * 8  # +4 for the length header
    
    # With matrix encoding, changes should be significantly fewer than payload bits
    # (for reasonable k values, approximately payload_bits / k changes)
    assert total_changes < total_payload_bits, (
        f"Matrix encoding should reduce changes. Got {total_changes} changes "
        f"for {total_payload_bits} payload bits."
    )

def test_adaptive_roundtrip(dummy_png, tmp_path):
    out_path = str(tmp_path / "stego.png")
    payload = b"Test payload for Adaptive algorithm"
    
    embed_adaptive(dummy_png, out_path, payload)
    
    assert os.path.exists(out_path)
    
    extracted = extract_adaptive(out_path)
    assert extracted == payload

def test_adaptive_texture_mask_invariance(dummy_png):
    """Verify that the texture mask is identical before and after LSB modification."""
    img = Image.open(dummy_png)
    arr = np.array(img)
    
    mask_before = get_texture_mask(arr)
    
    # Simulate LSB modification (flip all LSBs)
    modified = arr.copy()
    modified = modified ^ 1
    
    mask_after = get_texture_mask(modified)
    
    assert np.array_equal(mask_before, mask_after), \
        "Texture mask must be invariant to LSB changes"

def test_f5_capacity_error(dummy_jpeg, tmp_path):
    out_path = str(tmp_path / "stego.jpg")
    # 256x256 image won't hold 100kb
    huge_payload = os.urandom(100 * 1024) 
    
    with pytest.raises(ValueError, match="Payload too large|Hit capacity limit"):
         embed_f5_jpeg(dummy_jpeg, out_path, huge_payload, password="test")

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
