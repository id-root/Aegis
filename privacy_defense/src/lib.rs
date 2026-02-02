use core_engine::{Image, ImageFormat};
use image::{load_from_memory, ImageOutputFormat};
use std::io::{self, Cursor};

pub trait Sanitizer {
    fn sanitize(&self, image: &Image) -> io::Result<Vec<u8>>;
}

pub struct JpegSanitizer;

impl Sanitizer for JpegSanitizer {
    fn sanitize(&self, image: &Image) -> io::Result<Vec<u8>> {
        if image.format != ImageFormat::Jpeg {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Not a JPEG image"));
        }

        // Nuclear Option: Decode -> Destroy -> Re-encode
        let img = load_from_memory(&image.data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        let mut output = Vec::new();
        let mut cursor = Cursor::new(&mut output);

        // Re-encode as JPEG. This naturally strips undefined metadata unless explicitly copied.
        img.write_to(&mut cursor, ImageOutputFormat::Jpeg(90))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{RgbImage, ImageFormat as ImgFmt};

    #[test]
    fn test_sanitize_jpeg_reencoding() {
        // Create a small image
        let mut img = RgbImage::new(10, 10);
        for pixel in img.pixels_mut() {
            *pixel = image::Rgb([255, 0, 0]);
        }
        
        let mut buffer = Vec::new();
        img.write_to(&mut Cursor::new(&mut buffer), ImgFmt::Jpeg).unwrap();
        
        let image = Image {
            data: buffer,
            format: ImageFormat::Jpeg,
        };
        
        let sanitizer = JpegSanitizer;
        let result = sanitizer.sanitize(&image).unwrap();
        
        // Check if it's a valid JPEG
        assert!(result.starts_with(&[0xFF, 0xD8]));
        assert!(result.ends_with(&[0xFF, 0xD9]));
        
        // Ensure it can be loaded back
        let reloaded = image::load_from_memory(&result).unwrap();
        assert_eq!(reloaded.width(), 10);
        assert_eq!(reloaded.height(), 10);
    }
}
