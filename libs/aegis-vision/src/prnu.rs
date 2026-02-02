use image::DynamicImage;
use anyhow::{Result, anyhow};
use ndarray::Array2;

#[derive(Debug, Clone)]
pub struct VisionReport {
    pub dimensions: (u32, u32),
    pub noise_energy: f32, // Variance of noise
    pub min_noise: f32,
    pub max_noise: f32,
    pub fingerprint: Array2<f32>,
}

pub struct PrnuEngine;

impl PrnuEngine {
    pub fn new() -> Self {
        PrnuEngine
    }

    /// Extract noise fingerprint/residue from an image.
    pub fn extract_fingerprint(&self, img: &DynamicImage) -> Result<VisionReport> {
        let gray = img.to_luma8();
        let (width, height) = gray.dimensions();
        
        // Safety Check: Prevent DOS via massive allocation
        if width > 8192 || height > 8192 {
            return Err(anyhow!("Image dimensions too large for analysis ({0}x{1}). Max 8192x8192.", width, height));
        }
        if width < 4 || height < 4 {
             return Err(anyhow!("Image too small for analysis."));
        }
        
        let mut noise = Array2::<f32>::zeros((height as usize, width as usize));
        
        // Convert to f32 ndarray
        let mut signal = Array2::<f32>::zeros((height as usize, width as usize));
        for (x, y, pixel) in gray.enumerate_pixels() {
            signal[[y as usize, x as usize]] = pixel.0[0] as f32;
        }

        let mut min_val = f32::MAX;
        let mut max_val = f32::MIN;
        let mut sum_sq = 0.0;
        let mut count = 0;

        // Apply simple denoising (3x3 mean filter) and subtract
        // Loop excluding borders
        for y in 1..height as usize - 1 {
            for x in 1..width as usize - 1 {
                let mut sum = 0.0;
                for dy in 0..3 {
                    for dx in 0..3 {
                        sum += signal[[y + dy - 1, x + dx - 1]];
                    }
                }
                let smoothed = sum / 9.0;
                let original = signal[[y, x]];
                let n_val = original - smoothed;
                
                noise[[y, x]] = n_val;
                
                if n_val < min_val { min_val = n_val; }
                if n_val > max_val { max_val = n_val; }
                sum_sq += n_val * n_val;
                count += 1;
            }
        }
        
        let noise_energy = if count > 0 { sum_sq / count as f32 } else { 0.0 };

        Ok(VisionReport {
            dimensions: (width, height),
            noise_energy,
            min_noise: min_val,
            max_noise: max_val,
            fingerprint: noise,
        })
    }

    /// Calculate correlation between two fingerprints (Normalized Cross Correlation)
    pub fn correlate(&self, fp1: &Array2<f32>, fp2: &Array2<f32>) -> f32 {
        if fp1.dim() != fp2.dim() {
            return 0.0;
        }

        let flat1 = fp1.as_slice_memory_order().unwrap();
        let flat2 = fp2.as_slice_memory_order().unwrap();

        let mean1 = flat1.iter().sum::<f32>() / flat1.len() as f32;
        let mean2 = flat2.iter().sum::<f32>() / flat2.len() as f32;

        let mut num = 0.0;
        let mut den1 = 0.0;
        let mut den2 = 0.0;

        for (&v1, &v2) in flat1.iter().zip(flat2.iter()) {
            let d1 = v1 - mean1;
            let d2 = v2 - mean2;
            num += d1 * d2;
            den1 += d1 * d1;
            den2 += d2 * d2;
        }

        if den1 == 0.0 || den2 == 0.0 {
            0.0
        } else {
            num / (den1.sqrt() * den2.sqrt())
        }
    }
}
