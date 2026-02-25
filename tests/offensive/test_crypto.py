import pytest
from aegis.offensive.crypto import encrypt_payload, decrypt_payload, prepare_stego_payload, parse_stego_payload

def test_encryption_decryption_roundtrip():
    data = b"Secret payload data for testing."
    password = "super_secure_password123"
    
    encrypted = encrypt_payload(data, password)
    assert len(encrypted) > len(data)
    
    decrypted = decrypt_payload(encrypted, password)
    assert decrypted == data

def test_decryption_wrong_password():
    data = b"Secret payload data for testing."
    password = "super_secure_password123"
    wrong_password = "wrong_password123"
    
    encrypted = encrypt_payload(data, password)
    
    with pytest.raises(ValueError):
        decrypt_payload(encrypted, wrong_password)

def test_payload_framing_no_decoy():
    primary = b"Primary target data."
    password = "primary_password"
    
    framed = prepare_stego_payload(primary, password)
    
    extracted = parse_stego_payload(framed, password)
    assert extracted == primary

def test_payload_framing_with_decoy():
    primary = b"Top secret primary data."
    primary_pw = "primary_password"
    decoy = b"Harmless decoy data."
    decoy_pw = "decoy_password"
    
    framed = prepare_stego_payload(primary, primary_pw, decoy, decoy_pw)
    
    # Extract with primary password
    ext_primary = parse_stego_payload(framed, primary_pw)
    assert ext_primary == primary
    
    # Extract with decoy password
    ext_decoy = parse_stego_payload(framed, decoy_pw)
    assert ext_decoy == decoy

def test_payload_framing_wrong_password():
    primary = b"Primary target data."
    password = "primary_password"
    
    framed = prepare_stego_payload(primary, password)
    
    with pytest.raises(ValueError, match="Decryption failed for all available payloads"):
        parse_stego_payload(framed, "wrong_password")
