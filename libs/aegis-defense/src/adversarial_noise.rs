use image::RgbImage;
use rand::Rng;

pub struct AdversarialCloak;

impl AdversarialCloak {
    pub fn apply_anti_hog(image: &mut RgbImage, alpha: f32) {
        let (width, height) = image.dimensions();
        let mut rng = rand::thread_rng();

        // Apply checkerboard dither
        // Purpose: Introduce high-frequency noise that confuses Histogram of Oriented Gradients (HOG)
        // commonly used in face detection steps.
        
        for y in 0..height {
            for x in 0..width {
                // Checkerboard pattern
                let is_even = (x + y) % 2 == 0;
                let noise_sign = if is_even { 1.0 } else { -1.0 };
                
                // Random intensity within limit
                let intensity: f32 = rng.gen_range(0.0..1.0);
                let delta = noise_sign * intensity * alpha * 255.0;

                let pixel = image.get_pixel_mut(x, y);
                
                for c in 0..3 {
                    let old_val = pixel[c] as f32;
                    let new_val = (old_val + delta).clamp(0.0, 255.0);
                    pixel[c] = new_val as u8;
                }
            }
        }
    }
}
