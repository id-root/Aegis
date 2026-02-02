use std::fs;
use std::path::Path;
use anyhow::{Result, Context};

pub struct Carver;

impl Carver {
    /// Extracts data from `buffer` starting at `offset`.
    /// If `len` is provided, extracts exactly that many bytes.
    /// Otherwise, extracts until EOF (useful for appended archives like GIFAR).
    pub fn extract(data: &[u8], offset: usize, len: Option<usize>) -> Vec<u8> {
        if offset >= data.len() {
            return Vec::new();
        }
        
        match len {
            Some(l) => {
                let end = std::cmp::min(offset + l, data.len());
                data[offset..end].to_vec()
            }
            None => data[offset..].to_vec(),
        }
    }

    /// Saves extracted data to disk
    pub fn save_extraction(data: &[u8], base_path: &Path, name_suffix: &str) -> Result<String> {
        let parent = base_path.parent().unwrap_or(Path::new("."));
        let stem = base_path.file_stem().unwrap_or_default().to_string_lossy();
        let ext_dir = parent.join(format!("{}_extracted", stem));
        
        if !ext_dir.exists() {
            fs::create_dir_all(&ext_dir).context("Failed to create extraction directory")?;
        }

        let output_filename = format!("extracted_{}.bin", name_suffix);
        let output_path = ext_dir.join(&output_filename);
        
        fs::write(&output_path, data).context("Failed to write extracted file")?;
        
        Ok(output_path.to_string_lossy().to_string())
    }
}
