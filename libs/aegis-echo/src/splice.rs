use anyhow::Result;

pub struct SilenceDetector {
    threshold_db: f32,
}

impl SilenceDetector {
    pub fn new(threshold_db: f32) -> Self {
        SilenceDetector { threshold_db }
    }

    pub fn scan(&self, samples: &[f32]) -> Result<Vec<(usize, usize)>> {
        let mut segments = Vec::new();
        let mut start_idx = None;

        for (i, &sample) in samples.iter().enumerate() {
            let db = 20.0 * sample.abs().log10();
            
            if db < self.threshold_db {
                if start_idx.is_none() {
                    start_idx = Some(i);
                }
            } else {
                if let Some(start) = start_idx {
                    if i - start > 1000 { // Min duration check
                        segments.push((start, i));
                    }
                    start_idx = None;
                }
            }
        }
        
        Ok(segments)
    }
}
