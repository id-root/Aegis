use image::{DynamicImage, Rgba};

pub struct GlitchEngine;

impl GlitchEngine {
    /// Applies pixel sorting to obfuscate image content while maintaining 'artistic' values.
    /// This breaks OCR and edge detection by displacing pixels horizontally based on luminance.
    pub fn pixel_sort(img: &DynamicImage) -> DynamicImage {
        let mut output = img.to_rgba8();
        let (width, height) = output.dimensions();
        
        // Sort spans row by row
        for y in 0..height {
            let mut x = 0;
            while x < width {
                let start = x;
                let mut end = x;
                
                // Find span of "mid-tone" pixels to melt
                // Thresholds can be randomized for more chaos
                while end < width {
                    let p = output.get_pixel(end, y);
                    let brightness = (p[0] as u16 + p[1] as u16 + p[2] as u16) / 3;
                    // Sort regions that are not too dark and not too white
                    if brightness < 50 || brightness > 200 { break; }
                    end += 1;
                }
                
                if end > start + 1 {
                    // Sort this span
                    let len = end - start;
                    let mut span: Vec<Rgba<u8>> = (0..len).map(|i| *output.get_pixel(start + i, y)).collect();
                    // Sort by luminance
                    span.sort_by_key(|p| p[0] as u16 + p[1] as u16 + p[2] as u16);
                    
                    for (i, p) in span.iter().enumerate() {
                        output.put_pixel(start + i as u32, y, *p);
                    }
                }
                x = end + 1;
            }
        }
        DynamicImage::ImageRgba8(output)
    }
}
