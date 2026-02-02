use image::{DynamicImage, RgbImage, Rgb, ImageOutputFormat};
use std::io::Cursor;

pub fn analyze(image: &DynamicImage) -> RgbImage {
    let original = image.to_rgb8();
    let (width, height) = original.dimensions();

    // Re-compress at 95% quality
    let mut buffer = Vec::new();
    let mut cursor = Cursor::new(&mut buffer);
    image.write_to(&mut cursor, ImageOutputFormat::Jpeg(95)).unwrap();

    let recompressed = image::load_from_memory(&buffer).unwrap().to_rgb8();

    let mut heatmap = RgbImage::new(width, height);

    for (x, y, pixel) in heatmap.enumerate_pixels_mut() {
        let p1 = original.get_pixel(x, y);
        let p2 = recompressed.get_pixel(x, y);

        let r_diff = (p1[0] as i16 - p2[0] as i16).abs() as u8;
        let g_diff = (p1[1] as i16 - p2[1] as i16).abs() as u8;
        let b_diff = (p1[2] as i16 - p2[2] as i16).abs() as u8;

        // Scale by 20 (Gamma Correction approximation for visualization)
        let r_out = r_diff.saturating_mul(20);
        let g_out = g_diff.saturating_mul(20);
        let b_out = b_diff.saturating_mul(20);

        *pixel = Rgb([r_out, g_out, b_out]);
    }

    heatmap
}
