use image::DynamicImage;

pub fn extract_fingerprint(image: &DynamicImage) -> Vec<f32> {
    // Convert to Grayscale (PRNU is usually calculated on luminance)
    let gray = image.to_luma8();
    let (width, height) = gray.dimensions();
    
    // Denoise using simple box blur or gaussian
    // Residual = Image - Denoised
    // We cast to f32 for precision
    let mut residual = Vec::with_capacity((width * height) as usize);
    
    // Simple 3x3 box blur or just subtract local mean?
    // Using image::imageops::blur is Gaussian.
    let denoised = image::imageops::blur(&gray, 2.0); // sigma 2.0
    
    for (x, y, pixel) in gray.enumerate_pixels() {
        let val = pixel.0[0] as f32;
        let d_val = denoised.get_pixel(x, y).0[0] as f32;
        residual.push(val - d_val);
    }
    
    residual
}

pub fn compare(fingerprint: &[f32], reference: &[f32]) -> f64 {
    if fingerprint.len() != reference.len() {
        return 0.0;
    }
    
    // Normalized Cross Correlation (NCC)
    // NCC = dot(A, B) / (norm(A) * norm(B))
    
    let mut dot = 0.0;
    let mut norm_a_sq = 0.0;
    let mut norm_b_sq = 0.0;
    
    for i in 0..fingerprint.len() {
        let a = fingerprint[i] as f64;
        let b = reference[i] as f64;
        
        dot += a * b;
        norm_a_sq += a * a;
        norm_b_sq += b * b;
    }
    
    if norm_a_sq == 0.0 || norm_b_sq == 0.0 {
        return 0.0;
    }
    
    dot / (norm_a_sq.sqrt() * norm_b_sq.sqrt())
}
