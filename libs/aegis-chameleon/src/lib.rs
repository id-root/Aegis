use anyhow::{Result, Context};
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

pub mod pdf_html;
// pub mod gifar; // If we wanted to split it, but current impl is inline. Let's keep inline Chameleon struct for now but add pdf_html.

pub use pdf_html::PdfHtmlPolyglot;

pub struct Chameleon;

impl Chameleon {
    /// Generates a GIFAR (GIF + JAR/ZIP) polyglot.
    /// This file is a valid image (GIF) and a valid archive (ZIP/JAR).
    /// Many older java uploaders would accept this as an image, but it could be executed as a JAR.
    pub fn generate_gifar<P: AsRef<Path>>(
        image_path: P,
        archive_path: P,
        output_path: P,
    ) -> Result<()> {
        let image_data = fs::read(&image_path).context("Failed to read carrier image")?;
        let archive_data = fs::read(&archive_path).context("Failed to read payload archive")?;
        
        // Simple distinct concatenation
        // GIF header is at start. ZIP Central Directory is at end.
        let mut output = File::create(output_path)?;
        output.write_all(&image_data)?;
        output.write_all(&archive_data)?;
        
        Ok(())
    }
}
