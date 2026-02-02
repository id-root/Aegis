use byteorder::{WriteBytesExt, LittleEndian};
use std::io::{self};

pub struct MetadataPoisoner;

impl MetadataPoisoner {
    pub fn inject_infinite_loop_tiffs(target_buffer: &mut Vec<u8>) -> io::Result<()> {
        // Technique: Create two IFDs (Image File Directories) that point to each other.
        // Scrapers following the 'NextIFD' offset will loop indefinitely.
        
        let start_offset = target_buffer.len() as u32;
        
        // IFD A: Offset X -> IFD B
        // IFD B: Offset Y -> IFD A
        
        // Simulate appending an IFD A
        // Count: 0 tags
        target_buffer.write_u16::<LittleEndian>(0)?; 
        // Next IFD Offset points to where IFD B will be (Start + 6 bytes)
        target_buffer.write_u32::<LittleEndian>(start_offset + 6)?;
        
        // IFD B
        // Count: 0 tags
        target_buffer.write_u16::<LittleEndian>(0)?;
        // Next IFD Offset points back to IFD A
        target_buffer.write_u32::<LittleEndian>(start_offset)?;
        
        // Note: This is an abstract representation. In a real file, these need to be placed 
        // carefully in the file structure logic (not just appended) for valid parsers to encounter them
        // but not break the image display. For "The Mirage", we assume we are generating a "honey-token" file.
        
        println!("Injected recursive IFD reference at offset {}", start_offset);
        Ok(())
    }
}
