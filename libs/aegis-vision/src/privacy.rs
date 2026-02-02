use rustface::{Detector, ImageData, FaceInfo};
use image::{DynamicImage, GenericImage};
use anyhow::{Result, anyhow};
use std::path::Path;

pub struct FaceRedactor {
    detector: Box<dyn Detector>,
}

impl FaceRedactor {
    pub fn new<P: AsRef<Path>>(model_path: P) -> Result<Self> {
        let file = std::fs::File::open(model_path.as_ref())
            .map_err(|e| anyhow!("Failed to open SeetaFace model file: {}", e))?;
        let model = rustface::read_model(file)
             .map_err(|e| anyhow!("Failed to parse SeetaFace model: {:?}", e))?;
        let detector = rustface::create_detector_with_model(model);
        Ok(Self { detector })
    }

    pub fn redact_faces(&mut self, img: &DynamicImage) -> Result<(DynamicImage, usize)> {
        let gray = img.to_luma8();
        let (width, height) = gray.dimensions();
        let mut image_data = ImageData::new(&gray, width, height);

        let faces: Vec<FaceInfo> = self.detector.detect(&mut image_data);
        let count = faces.len();

        let mut output = img.clone();
        
        for face in faces {
            let bbox = face.bbox();
            let x = bbox.x().max(0) as u32;
            let y = bbox.y().max(0) as u32;
            let w = (bbox.width() as u32).min(width.saturating_sub(x));
            let h = (bbox.height() as u32).min(height.saturating_sub(y));
            
            // Pixelate region
            let region = output.crop_imm(x, y, w, h);
            let pixelated = image::imageops::resize(&region, w / 10 + 1, h / 10 + 1, image::imageops::FilterType::Nearest);
            let restored = image::imageops::resize(&pixelated, w, h, image::imageops::FilterType::Nearest);
            
            // Overlay pixelated
            for (dx, dy, pixel) in restored.enumerate_pixels() {
                if x + dx < width && y + dy < height {
                     output.put_pixel(x + dx, y + dy, *pixel);
                }
            }
        }

        Ok((output, count))
    }
}
