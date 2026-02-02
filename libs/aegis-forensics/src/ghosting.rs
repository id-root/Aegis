use image::{DynamicImage, ImageOutputFormat};
use std::io::Cursor;
use rayon::prelude::*;

pub fn detect_double_compression(image: &DynamicImage) -> Vec<(u8, f64)> {
    let original = image.to_rgb8();
    let (width, height) = original.dimensions();
    let total_pixels = (width * height) as f64;

    // Parallel iterator over quality levels
    (60..=100).into_par_iter().map(|q| {
        let mut buffer = Vec::new();
        let mut cursor = Cursor::new(&mut buffer);
        
        // Re-compress
        image.write_to(&mut cursor, ImageOutputFormat::Jpeg(q)).unwrap();
        
        // Load back
        let recompressed = image::load_from_memory(&buffer).unwrap().to_rgb8();
        
        // Calculate MSE
        let mut sum_sq_diff = 0.0;
        for (x, y, pixel) in original.enumerate_pixels() {
            let p2 = recompressed.get_pixel(x, y);
            
            for c in 0..3 {
                let diff = pixel[c] as f64 - p2[c] as f64;
                sum_sq_diff += diff * diff;
            }
        }
        
        // RMSE (per channel per pixel approx, usually averaged)
        let mse = sum_sq_diff / (total_pixels * 3.0);
        let rmse = mse.sqrt();
        
        (q, rmse)
    }).collect()
}
