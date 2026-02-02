use image::{DynamicImage, GenericImageView, Pixel};

/// Analyzes the Least Significant Bit plane of an image.
/// Returns a ratio of high-variance pixels vs total pixels.
/// A high ratio suggests LSB steganography or just high noise.
pub fn analyze_lsb(image: &DynamicImage) -> f64 {
    let (width, height) = image.dimensions();
    let total_pixels = (width * height) as f64;
    let mut high_variance_count = 0;

    for (_x, _y, pixel) in image.pixels() {
        let rgba = pixel.to_rgba();
        let r = rgba[0];
        let g = rgba[1];
        let b = rgba[2];

        // Check if LSBs are flipped (simple heuristic check for noise density)
        // If the LSB is 1, it contributes to "noise".
        if (r & 1) == 1 { high_variance_count += 1; }
        if (g & 1) == 1 { high_variance_count += 1; }
        if (b & 1) == 1 { high_variance_count += 1; }
    }
    
    // Normalize by 3 channels
    let metric = (high_variance_count as f64) / (total_pixels * 3.0);
    metric
}
