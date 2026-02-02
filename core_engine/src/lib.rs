use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

#[derive(Debug)]
pub struct Image {
    pub data: Vec<u8>,
    pub format: ImageFormat,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ImageFormat {
    Jpeg,
    Png,
    Unknown,
}

impl Image {
    pub fn load<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let mut file = File::open(path)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;

        let format = Self::detect_format(&data);

        Ok(Image { data, format })
    }

    fn detect_format(data: &[u8]) -> ImageFormat {
        if data.starts_with(&[0xFF, 0xD8, 0xFF]) {
            ImageFormat::Jpeg
        } else if data.starts_with(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) {
            ImageFormat::Png
        } else {
            ImageFormat::Unknown
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_load_jpeg_detection() {
        let filename = "test_image.jpg";
        let mut file = File::create(filename).unwrap();
        // JPEG magic bytes
        file.write_all(&[0xFF, 0xD8, 0xFF, 0xE0]).unwrap();

        let img = Image::load(filename).unwrap();
        assert_eq!(img.format, ImageFormat::Jpeg);
        assert_eq!(img.data.len(), 4);

        std::fs::remove_file(filename).unwrap();
    }

    #[test]
    fn test_load_png_detection() {
        let filename = "test_image.png";
        let mut file = File::create(filename).unwrap();
        // PNG magic bytes
        file.write_all(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
            .unwrap();

        let img = Image::load(filename).unwrap();
        assert_eq!(img.format, ImageFormat::Png);

        std::fs::remove_file(filename).unwrap();
    }
}
