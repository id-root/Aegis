use regex::bytes::Regex;
use crate::ThreatMatch;

pub fn scan(data: &[u8]) -> Vec<ThreatMatch> {
    // Extended patterns
    let patterns = [
        ("Web Shell", r"(?i)(<script>|eval\(|base64_decode|javascript:|vbscript:|powershell|cmd\.exe)"),
        ("ELF Binary", r"\x7FELF"),
        ("PDF Document", r"%PDF-"),
        ("PHP Open Tag", r"<\?php"),
    ];
    
    let mut found = Vec::new();

    for (desc, pattern) in patterns.iter() {
        if let Ok(re) = Regex::new(pattern) {
             for mat in re.find_iter(data) {
                found.push(ThreatMatch {
                    name: "Signature".to_string(),
                    description: format!("{} detected", desc),
                    offset: mat.start(),
                    snippet: mat.as_bytes().iter().take(16).cloned().collect(),
                });
            }
        }
    }
    
    found
}
