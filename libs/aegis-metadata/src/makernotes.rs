use std::io::Cursor;
use exif::Reader;

#[derive(Debug, Clone)]
pub struct TagValue {
    pub id: u16,
    pub name: String,
    pub value: String,
}

pub struct MakerNoteDecoder;

impl MakerNoteDecoder {
    pub fn new() -> Self {
        MakerNoteDecoder
    }

    pub fn decode(&self, _vendor_hint: &str, data: &[u8]) -> Option<Vec<TagValue>> {
        let reader = Reader::new();
        let mut tags = Vec::new();

        // Attempt to parse Exif data from the byte slice
        if let Ok(exif) = reader.read_from_container(&mut Cursor::new(data)) {
            for field in exif.fields() {
                let tag_str = field.tag.to_string();
                let display_value = field.display_value().with_unit(&exif).to_string();
                
                // Helper to extract u16 ID from tag (Tag is an enum, we use a simple hash/match if needed, 
                // but for now we iterate standard tags).
                // Actually `field.tag.number()` exists in kamadak-exif.
                let id = field.tag.number();

                tags.push(TagValue {
                    id,
                    name: tag_str,
                    value: display_value,
                });
            }
        }
        
        if tags.is_empty() {
             None
        } else {
             Some(tags)
        }
    }
}
