pub mod ela;
pub mod ghosting;
pub mod prnu;
pub mod entropy;
pub mod lsb;
pub mod carver;

#[cfg(test)]
mod tests {
    use super::*;
    use image::{RgbImage, DynamicImage, Rgb};

    fn create_dummy_image() -> DynamicImage {
        let mut img = RgbImage::new(50, 50);
        for pixel in img.pixels_mut() {
            *pixel = Rgb([100, 150, 200]);
        }
        DynamicImage::ImageRgb8(img)
    }

    #[test]
    fn test_ela() {
        let img = create_dummy_image();
        let heatmap = ela::analyze(&img);
        assert_eq!(heatmap.width(), 50);
        assert_eq!(heatmap.height(), 50);
    }

    #[test]
    fn test_ghosting() {
        let img = create_dummy_image();
        let result = ghosting::detect_double_compression(&img);
        assert_eq!(result.len(), 41); // 60 to 100 inclusive
    }

    #[test]
    fn test_prnu_self_correlation() {
        // Use a semi-random pattern based on coords
        let mut img = RgbImage::new(50, 50);
        for (x, y, pixel) in img.enumerate_pixels_mut() {
            let r = ((x * y) % 255) as u8;
            let g = ((x + y) % 255) as u8;
            let b = ((x * x + y) % 255) as u8;
            *pixel = Rgb([r, g, b]);
        }
        let dynamic = DynamicImage::ImageRgb8(img);
        
        let fp = prnu::extract_fingerprint(&dynamic);
        // Ensure fingerprint is not all zeros (flat image would be 0)
        let sum: f32 = fp.iter().map(|&x| x.abs()).sum();
        assert!(sum > 0.0);
        
        let score = prnu::compare(&fp, &fp);
        assert!((score - 1.0).abs() < 0.0001);
    }
}
