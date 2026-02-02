use std::f64;

#[derive(Debug, Clone)]
pub struct EntropyReport {
    pub global_entropy: f64,
    pub min_entropy: f64,
    pub max_entropy: f64,
    pub mean_entropy: f64,
    pub distribution: Vec<(f32, f32)>, // For plotting (x=chunk_idx, y=entropy)
}

/// Calculates the Shannon Entropy of a byte slice.
/// Returns a value between 0.0 (constant) and 8.0 (completely random/encrypted).
pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut frequencies = [0u64; 256];
    for &byte in data {
        frequencies[byte as usize] += 1;
    }

    let total_len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &frequencies {
        if count > 0 {
            let probability = count as f64 / total_len;
            entropy -= probability * probability.log2();
        }
    }

    entropy
}

/// Analyzes entropy of a file in sliding windows to detect hidden payloads.
pub fn analyze_chunks(data: &[u8]) -> EntropyReport {
    let window_size = 256;
    let step = 128; // Overlap by half
    
    if data.len() < window_size {
        let ent = calculate_entropy(data);
        return EntropyReport {
            global_entropy: ent,
            min_entropy: ent,
            max_entropy: ent,
            mean_entropy: ent,
            distribution: vec![(0.0, ent as f32)],
        };
    }

    let mut entropies = Vec::new();
    let mut min_e = 8.0;
    let mut max_e = 0.0;
    let mut sum_e = 0.0;

    // Sliding window
    for (i, window) in data.windows(window_size).step_by(step).enumerate() {
        let ent = calculate_entropy(window);
        entropies.push((i as f32, ent as f32));
        
        if ent < min_e { min_e = ent; }
        if ent > max_e { max_e = ent; }
        sum_e += ent;
    }

    let global = calculate_entropy(data);
    let mean = if !entropies.is_empty() { sum_e / entropies.len() as f64 } else { global };

    EntropyReport {
        global_entropy: global,
        min_entropy: min_e,
        max_entropy: max_e,
        mean_entropy: mean,
        distribution: entropies,
    }
}
