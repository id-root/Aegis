use crate::ThreatMatch;

pub fn scan(data: &[u8]) -> Vec<ThreatMatch> {
    let mut matches = Vec::new();

    if !is_jpeg(data) {
        // If it's not a JPEG, we might still want to check for other things,
        // but for now we follow the logic: check if JPEG contains foreign bodies.
        // Actually, let's just scan for foreign headers regardless of container.
    }
    
    // Scan for ZIP Local File Header: 50 4B 03 04 (PK\x03\x04)
    let zip_magic = [0x50, 0x4B, 0x03, 0x04];
    
    for (i, window) in data.windows(4).enumerate() {
        if window == zip_magic {
            // Filter false positives: ZIP header usually not at 0 unless it IS a zip.
            // If it is at 0, it's just a ZIP file, not necessarily a polyglot (unless extension says jpg).
            // But 'scan' tool logic handles context. Here we just report findings.
            
            // Avoid flagging the start of a legitimate ZIP as a "Threat" unless context implies.
            // But detailed report should just list it.
            if i > 0 {
                 matches.push(ThreatMatch {
                    name: "Polyglot".to_string(),
                    description: "ZIP Archive Header (PK) found embedded".to_string(),
                    offset: i,
                    snippet: window.to_vec(),
                });
            }
        }
    }
    
    matches
}

fn is_jpeg(data: &[u8]) -> bool {
    data.len() > 2 && data[0] == 0xFF && data[1] == 0xD8
}
