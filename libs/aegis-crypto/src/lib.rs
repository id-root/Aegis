pub mod encryption;
pub mod stego;

#[cfg(test)]
mod tests {
    use super::*;
    use image::{RgbImage, Rgb, DynamicImage};
    use rand::{Rng, RngCore};

    #[test]
    fn test_encryption_roundtrip() {
        let password = "supersecretpassword";
        let data = b"Hello World! This is a secret.";
        
        let encrypted = encryption::encrypt(data, password).unwrap();
        assert_ne!(data, encrypted.as_slice());
        
        let decrypted = encryption::decrypt(&encrypted, password).unwrap();
        assert_eq!(data, decrypted.as_slice());
    }

    #[test]
    fn test_encryption_wrong_password() {
        let data = b"Sensitive";
        let encrypted = encryption::encrypt(data, "pass1").unwrap();
        let result = encryption::decrypt(&encrypted, "pass2");
        assert!(result.is_err());
    }

    #[test]
    fn test_stego_roundtrip() {
        // Create a noisy image (random noise) to ensure high complexity blocks exist
        let width = 64;
        let height = 64;
        let mut img = RgbImage::new(width, height);
        let mut rng = rand::thread_rng();
        
        for pixel in img.pixels_mut() {
            *pixel = Rgb([rng.r#gen(), rng.r#gen(), rng.r#gen()]);
        }

        let dynamic_img = DynamicImage::ImageRgb8(img);
        
        // Payload: Encrypted-like data (random)
        let mut payload = [0u8; 100];
        rng.fill_bytes(&mut payload);
        
        // Embed
        let embedded_img = stego::embed(dynamic_img, &payload).expect("Embedding failed");
        
        // Extract
        let extracted = stego::extract(embedded_img).expect("Extraction failed");
        
        assert_eq!(payload.to_vec(), extracted);
    }
}
