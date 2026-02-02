pub mod enf;
pub mod splice;
pub mod spectrogram;

pub use enf::EnfExtractor;
pub use splice::SilenceDetector;
pub use spectrogram::generate_spectrogram_image;

use std::path::Path;
use std::fs::File;
use symphonia::core::io::MediaSourceStream;
use symphonia::core::audio::Signal;
use symphonia::core::errors::Error as SymphoniaError;
use anyhow::{Result, anyhow, Context};

use rustfft::{FftPlanner, num_complex::Complex};
use textplots::{Chart, Plot, Shape};

#[derive(Debug, Clone)]
pub struct AudioReport {
    pub duration_seconds: f64,
    pub sample_rate: u32,
    pub channels: usize,
    pub clipping_percentage: f32, // Ratio of samples > 0.99
    pub silence_regions: Vec<(f64, f64)>, // Start/End in seconds
    pub spectrum_ascii: String,
}

pub fn analyze_full(samples: &[f32], sample_rate: u32) -> AudioReport {
    let duration = samples.len() as f64 / sample_rate as f64;
    
    // Clipping Analysis
    let clipped_count = samples.iter().filter(|&&s| s.abs() > 0.99).count();
    let clipping_ratio = clipped_count as f32 / samples.len() as f32;

    // Silence Detection (Simple Threshold)
    let threshold = 0.001; // -60dB approx
    let mut silence_regions = Vec::new();
    let mut in_silence = false;
    let mut start_time = 0.0;

    for (i, &s) in samples.iter().enumerate() {
        let is_silent = s.abs() < threshold;
        let time = i as f64 / sample_rate as f64;

        if is_silent && !in_silence {
            in_silence = true;
            start_time = time;
        } else if !is_silent && in_silence {
            in_silence = false;
            // Filter short glitches (< 0.1s)
            if time - start_time > 0.1 {
                silence_regions.push((start_time, time));
            }
        }
    }
    // Close open region
    if in_silence {
         silence_regions.push((start_time, duration));
    }

    let spectrum = analyze_spectrum(samples, sample_rate);

    AudioReport {
        duration_seconds: duration,
        sample_rate,
        channels: 1, // Simplified mono
        clipping_percentage: clipping_ratio,
        silence_regions,
        spectrum_ascii: spectrum,
    }
}

pub fn analyze_spectrum(samples: &[f32], sample_rate: u32) -> String {
    // FFT Analysis on the first window (e.g., 1024 samples)
    let window_size = 1024;
    let effective_size = std::cmp::min(samples.len(), window_size);
    
    if effective_size == 0 {
        return "No Data".to_string();
    }

    let mut planner = FftPlanner::new();
    let fft = planner.plan_fft_forward(effective_size);
    
    let mut buffer: Vec<Complex<f32>> = samples.iter()
        .take(effective_size)
        .map(|&s| Complex { re: s, im: 0.0 })
        .collect();
        
    // Zero padding if needed
    if buffer.len() < window_size {
        buffer.resize(window_size, Complex { re: 0.0, im: 0.0 });
    }

    fft.process(&mut buffer);

    // Calculate magnitude for first half (Nyquist)
    let output_len = effective_size / 2;
    let points: Vec<(f32, f32)> = buffer.iter()
        .take(output_len)
        .enumerate()
        .map(|(i, c)| {
            let freq = i as f32 * sample_rate as f32 / effective_size as f32;
            let magnitude = c.norm();
            (freq, magnitude.ln().max(0.0) * 10.0) // Log scale for visibility
        })
        .collect();

    // Generate ASCII Chart
    let chart = Chart::new(100, 20, 0.0, (sample_rate / 2) as f32)
        .lineplot(&Shape::Lines(&points))
        .to_string();
        
    chart
}

pub fn load_audio<P: AsRef<Path>>(path: P) -> Result<(Vec<f32>, u32)> {
    let src = File::open(path).context("Failed to open audio file")?;
    let mss = MediaSourceStream::new(Box::new(src), Default::default());

    let probed = symphonia::default::get_probe().format(&Default::default(), mss, &Default::default(), &Default::default())
        .context("Failed to probe audio format")?;
        
    let mut format = probed.format;
    let track = format.default_track().ok_or(anyhow!("No default track"))?;
    let sample_rate = track.codec_params.sample_rate.unwrap_or(44100);
    
    let mut decoder = symphonia::default::get_codecs().make(&track.codec_params, &Default::default())
        .context("Failed to create decoder")?;
    let track_id = track.id;

    let mut samples: Vec<f32> = Vec::new();

    loop {
        let packet = match format.next_packet() {
            Ok(p) => p,
            Err(SymphoniaError::IoError(_)) => break, // EOF
            Err(e) if e.to_string().to_lowercase().contains("end of stream") => break, // Handle explicit "end of stream" error
            Err(e) => return Err(anyhow!("Format read error: {}", e)),
        };

        if packet.track_id() != track_id {
            continue;
        }

        match decoder.decode(&packet) {
            Ok(decoded) => {
                let mut buf = symphonia::core::audio::AudioBuffer::<f32>::new(decoded.capacity() as u64, *decoded.spec());
                decoded.convert(&mut buf);
                
                // Mixdown to mono for analysis (simplified: take channel 0)
                if buf.spec().channels.count() > 0 {
                    let plane_data = buf.chan(0);
                    samples.extend_from_slice(plane_data);
                }
            }
            Err(SymphoniaError::IoError(_)) => break, // EOF
            Err(e) if e.to_string().to_lowercase().contains("end of stream") => break,
            Err(SymphoniaError::DecodeError(_)) => continue, // Corrupt frame, skip
            Err(e) => return Err(anyhow!("Decode error: {}", e)),
        }
    }
    
    if samples.is_empty() {
        return Err(anyhow!("No audio samples decoded (Empty or corrupted file)"));
    }

    Ok((samples, sample_rate))
}
