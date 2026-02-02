use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, KeyInit};
use rand::{RngCore, rngs::OsRng};
use anyhow::{Result, anyhow};


pub struct EncryptionEngine {
    cipher: ChaCha20Poly1305,
}

impl EncryptionEngine {
    pub fn new(key: &[u8; 32]) -> Self {
        let key = Key::from_slice(key);
        let cipher = ChaCha20Poly1305::new(key);
        EncryptionEngine { cipher }
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes); // 96-bits; unique per message

        let ciphertext = self.cipher.encrypt(nonce, data)
            .map_err(|e| anyhow!("Encryption failure: {}", e))?;
        
        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        
        Ok(result)
    }

    pub fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>> {
        if encrypted_data.len() < 12 {
            return Err(anyhow!("Invalid ciphertext length"));
        }

        let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        self.cipher.decrypt(nonce, ciphertext)
            .map_err(|e| anyhow!("Decryption failure: {}", e))
    }
}
