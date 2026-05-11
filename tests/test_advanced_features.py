import os
import pytest
from aegis.core.signing import generate_key_pair, sign_image_hash_asymmetric, verify_image_signature_asymmetric
from aegis.security.shredder import secure_shred
from aegis.security.timestomp import clone_timestamps
from aegis.offensive.fs_stego import embed_xattr, extract_xattr

def test_ed25519_roundtrip():
    priv, pub = generate_key_pair()
    
    fake_hash = "a" * 64
    sig = sign_image_hash_asymmetric(fake_hash, priv)
    
    assert verify_image_signature_asymmetric(fake_hash, sig, pub) is True
    assert verify_image_signature_asymmetric("b" * 64, sig, pub) is False

def test_secure_shredder(tmp_path):
    test_file = str(tmp_path / "secret.txt")
    with open(test_file, "w") as f:
        f.write("Highly sensitive data")
        
    assert os.path.exists(test_file)
    
    success = secure_shred(test_file, passes=1) # 1 pass for speed in test
    
    assert success is True
    assert not os.path.exists(test_file)

def test_timestomp(tmp_path):
    ref_file = str(tmp_path / "reference.txt")
    target_file = str(tmp_path / "target.txt")
    
    with open(ref_file, "w") as f: f.write("ref")
    with open(target_file, "w") as f: f.write("target")
    
    # Manually set ref time to something old
    os.utime(ref_file, (1000000000, 1000000000))
    
    assert os.stat(target_file).st_mtime != 1000000000
    
    success = clone_timestamps(ref_file, target_file)
    
    assert success is True
    assert os.stat(target_file).st_mtime == 1000000000
    assert os.stat(target_file).st_atime == 1000000000

def test_fs_stego_xattr(tmp_path):
    # This test might fail if the underlying tmp_path filesystem doesn't support xattrs.
    # We will skip gracefully if OSError occurs during setxattr.
    carrier_file = str(tmp_path / "carrier.txt")
    with open(carrier_file, "w") as f:
        f.write("Normal content")
        
    payload = b"Super secret payload data"
    
    try:
        success = embed_xattr(carrier_file, payload)
        assert success is True
        
        extracted = extract_xattr(carrier_file)
        assert extracted == payload
        
        # Verify file content is unchanged
        with open(carrier_file, "r") as f:
            assert f.read() == "Normal content"
            
    except OSError:
        pytest.skip("Filesystem does not support xattrs")
