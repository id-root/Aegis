use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce
};
use argon2::{
    password_hash::{
        rand_core::RngCore,
        PasswordHasher, SaltString
    },
    Argon2
};
use anyhow::Result;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

pub fn encrypt(data: &[u8], password: &str) -> Result<Vec<u8>> {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    let key = derive_key(password, &salt)?;
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message

    let ciphertext = cipher.encrypt(&nonce, data)
        .map_err(|e| anyhow::anyhow!("Encryption failure: {}", e))?;

    let mut output = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
    output.extend_from_slice(&salt);
    output.extend_from_slice(nonce.as_slice());
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

pub fn decrypt(encrypted_data: &[u8], password: &str) -> Result<Vec<u8>> {
    if encrypted_data.len() < SALT_LEN + NONCE_LEN {
        return Err(anyhow::anyhow!("Data too short"));
    }

    let salt = &encrypted_data[..SALT_LEN];
    let nonce_bytes = &encrypted_data[SALT_LEN..SALT_LEN + NONCE_LEN];
    let ciphertext = &encrypted_data[SALT_LEN + NONCE_LEN..];

    let key = derive_key(password, salt)?;
    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("Decryption failure: {}", e))?;

    Ok(plaintext)
}

fn derive_key(password: &str, salt: &[u8]) -> Result<Key<Aes256Gcm>> {
    let argon2 = Argon2::default();
    
    // Convert generic salt bytes to SaltString required by Argon2 high-level API
    // Note: SaltString::encode_b64 handles the conversion to B64 format expected by PHC.
    let salt_string = SaltString::encode_b64(salt)
        .map_err(|e| anyhow::anyhow!("Salt encoding error: {}", e))?;

    let password_hash = argon2.hash_password(password.as_bytes(), salt_string.as_salt())
        .map_err(|e| anyhow::anyhow!("KDF failure: {}", e))?;

    let output = password_hash.hash
        .ok_or_else(|| anyhow::anyhow!("No hash output"))?;

    let mut key_bytes = [0u8; 32];
    let out_bytes = output.as_bytes();
    
    // Argon2 default output is 32 bytes, but let's be safe
    let len = std::cmp::min(key_bytes.len(), out_bytes.len());
    key_bytes[..len].copy_from_slice(&out_bytes[..len]);
    
    Ok(Key::<Aes256Gcm>::from(key_bytes))
}
