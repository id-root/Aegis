use image::DynamicImage;
use std::f64::consts::PI;

pub struct CfaIntegrityResult {
    pub has_bayer_periodicity: bool,
    pub resampling_detected: bool,
    pub variance_map: Vec<f64>,
}

pub fn verify_bayer_demosaicing(image: &DynamicImage) -> CfaIntegrityResult {
    let gray_image = image.to_luma8();
    let width = gray_image.width();
    let height = gray_image.height();

    // Simplified approach: Calculate variance of differences between neighbors
    // Genuine CFA interpolation leaves periodic traces in the variance of differences.
    // We check rows and columns for period 2.0 (Nyquist check).

    // Calculate row difference variances
    let mut row_variances = Vec::new();
    for y in 0..height {
        let mut diff_sq_sum = 0.0;
        let mut count = 0;
        for x in 0..width-1 {
            let p1 = gray_image.get_pixel(x, y)[0] as f64;
            let p2 = gray_image.get_pixel(x+1, y)[0] as f64;
            let diff = p1 - p2;
            diff_sq_sum += diff * diff;
            count += 1;
        }
        if count > 0 {
            row_variances.push(diff_sq_sum / count as f64);
        }
    }

    // Analyze periodicity in variances
    // We expect a strong peak at frequency 0.5 (period 2) for original CFA images
    let (peak_freq, peak_strength) = analyze_periodicity(&row_variances);

    // If the strongest frequency is close to 0.5 (Nyquist), it's likely original CFA.
    // If the peak is weak or displaced, resampling occurred.
    
    let has_bayer_periodicity = (peak_freq - 0.5).abs() < 0.05 && peak_strength > 0.1;
    let resampling_detected = !has_bayer_periodicity;

    CfaIntegrityResult {
        has_bayer_periodicity,
        resampling_detected,
        variance_map: row_variances,
    }
}

fn analyze_periodicity(signal: &[f64]) -> (f64, f64) {
    // Simple DFT for peak detection
    let n = signal.len();
    let mut max_magnitude = 0.0;
    let mut max_freq = 0.0;

    // Check frequencies from 0.0 to 0.5
    let step = 0.01;
    let mut freq = 0.01;
    while freq <= 0.5 {
        let mut real = 0.0;
        let mut imag = 0.0;
        
        for (t, &val) in signal.iter().enumerate() {
            let angle = 2.0 * PI * freq * t as f64;
            real += val * angle.cos();
            imag -= val * angle.sin();
        }

        let magnitude = (real * real + imag * imag).sqrt();
        if magnitude > max_magnitude {
            max_magnitude = magnitude;
            max_freq = freq;
        }
        
        freq += step;
    }

    // Normalize magnitude
    let avg_magnitude = max_magnitude / n as f64;
    (max_freq, avg_magnitude)
}
