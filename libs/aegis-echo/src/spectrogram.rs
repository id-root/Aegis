use image::{ImageBuffer, Rgb};
use rustfft::{FftPlanner, num_complex::Complex};
use anyhow::{Result, anyhow};

pub fn generate_spectrogram_image(samples: &[f32], _sample_rate: u32, output_path: &str) -> Result<()> {
    let window_size = 1024;
    let hop_size = 512;
    let width = 1024; // This was previously calculated based on samples.len()
    let height = 512; // This was previously calculated based on window_size
    
    // Check if enough samples
    if samples.len() < width as usize { // Use the new fixed width
        return Err(anyhow!("Not enough audio samples"));
    }

    // Limits
    // The following line from the original code is missing in the provided snippet,
    // but `draw_width` is used later. I will assume it should be kept.
    let draw_width = std::cmp::min(width, 4096); // Cap width
    
    // The user's provided snippet has a conflicting definition for `sample_limit`.
    // It first defines `_sample_limit` and then `sample_limit` using `draw_width` and `hop_size`.
    // I will assume the intent is to replace the original `sample_limit` with the new `_sample_limit`
    // and keep the `draw_width` calculation as it's used.
    let _sample_limit = 10 * 60 * 44100; // Limit to first 10 min

    let mut imgbuf = ImageBuffer::new(draw_width, height);
    let mut planner = FftPlanner::new();
    let fft = planner.plan_fft_forward(window_size);

    for x in 0..draw_width {
        let start = x as usize * hop_size;
        if start + window_size > samples.len() { break; }
        
        let chunk = &samples[start..start + window_size];
        let mut buffer: Vec<Complex<f32>> = chunk.iter().map(|&s| Complex { re: s, im: 0.0 }).collect();
        fft.process(&mut buffer);

        // Draw column (frequencies from 0 to Nyquist)
        // Y=0 is high freq usually in images? Or low?
        // Standard spectrogram: Low freq at bottom.
        
        for y in 0..height {
            let idx = y as usize; // 0 is DC
            let magnitude = buffer[idx].norm();
            let log_mag = (magnitude.ln() * 20.0).max(0.0); // dB-like
            
            // Heatmap color map (Blue -> Red -> Yellow)
            let color = heatmap_color(log_mag, 100.0); // Max dB approx 100
            
            // Invert Y so low freq is bottom
            imgbuf.put_pixel(x, height - 1 - y, color);
        }
    }

    imgbuf.save(output_path)?;
    Ok(())
}

fn heatmap_color(val: f32, max_val: f32) -> Rgb<u8> {
    let norm = (val / max_val).clamp(0.0, 1.0);
    // Simple gradient: Black -> Blue -> Red -> Yellow
    if norm < 0.25 {
        Rgb([0, 0, (norm * 4.0 * 255.0) as u8])
    } else if norm < 0.5 {
        Rgb([0, ((norm - 0.25) * 4.0 * 255.0) as u8, 255])
    } else if norm < 0.75 {
        Rgb([((norm - 0.5) * 4.0 * 255.0) as u8, 255, (255.0 - (norm - 0.5) * 4.0 * 255.0) as u8])
    } else {
        Rgb([255, 255, ((norm - 0.75) * 4.0 * 255.0) as u8])
    }
}
