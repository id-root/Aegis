pub mod polyglot;
pub mod signatures;

#[derive(Debug, Clone)]
pub struct ThreatMatch {
    pub name: String,
    pub description: String,
    pub offset: usize,
    pub snippet: Vec<u8>, // First 8-16 bytes of match
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_polyglot_detection() {
        let mut data = vec![0xFF, 0xD8, 0xFF, 0xE0]; // JPEG start
        data.extend_from_slice(b"some image data");
        data.extend_from_slice(&[0x50, 0x4B, 0x03, 0x04]); // ZIP header
        data.extend_from_slice(b"zip content");
        
        let matches = polyglot::scan(&data);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].name, "Polyglot");
    }

    #[test]
    fn test_clean_file_not_polyglot() {
        let data = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x00];
         let matches = polyglot::scan(&data);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_signatures_detection() {
        let data = b"Metadata: <script>alert('pwned')</script>";
        let matches = signatures::scan(data);
        assert!(!matches.is_empty());
        assert!(matches[0].description.contains("Web Shell"));
    }
}
