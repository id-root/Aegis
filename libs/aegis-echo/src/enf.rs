use rustfft::{FftPlanner, num_complex::Complex};
use anyhow::Result;

pub struct EnfExtractor {
    target_freq: f32, // 50.0 or 60.0 Hz
    sample_rate: u32,
    _window_size: usize,
}

impl EnfExtractor {
    pub fn new(target_freq: f32, sample_rate: u32) -> Self {
        EnfExtractor {
            target_freq,
            sample_rate,
            _window_size: 4096, // High resolution needed
        }
    }

    pub fn process_segment(&self, samples: &[f32]) -> Result<f32> {
        let mut planner = FftPlanner::new();
        let fft = planner.plan_fft_forward(samples.len());

        let mut buffer: Vec<Complex<f32>> = samples.iter()
            .map(|&s| Complex { re: s, im: 0.0 })
            .collect();

        fft.process(&mut buffer);
        
        // Find peak nearest to target_freq
        let bin_width = self.sample_rate as f32 / samples.len() as f32;
        let target_bin = (self.target_freq / bin_width) as usize;
        let search_radius = (2.0 / bin_width) as usize; // Search +/- 2Hz

        let start = target_bin.saturating_sub(search_radius);
        let end = (target_bin + search_radius).min(buffer.len() / 2);
        
        let mut max_mag = 0.0;
        let mut peak_freq = 0.0;

        for (i, bin) in buffer.iter().enumerate().take(end).skip(start) {
            let magnitude = bin.norm();
            if magnitude > max_mag {
                max_mag = magnitude;
                peak_freq = i as f32 * bin_width;
            }
        }

        Ok(peak_freq)
    }
}
