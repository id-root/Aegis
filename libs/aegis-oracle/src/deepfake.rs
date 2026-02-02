use crate::model::run_inference;
use anyhow::Result;

pub struct DeepfakeScanner;

impl DeepfakeScanner {
    pub fn new() -> Self {
        Self
    }
}

pub fn scan(data: &[u8]) -> Result<(f32, String)> {
    run_inference(data)
}
