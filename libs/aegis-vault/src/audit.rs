use blake3::Hasher;
use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuditEntry {
    pub prev_hash: String,
    pub timestamp: i64,
    pub action: String,
    pub user_id: String,
    pub resource_id: String,
}

pub struct AuditLog {
    last_hash: String,
}

impl AuditLog {
    pub fn new() -> Self {
        AuditLog {
            last_hash: "00000000000000000000000000000000".to_string(), // Genesis hash
        }
    }

    pub fn append(&mut self, action: &str, resource: &str) -> AuditEntry {
        let entry = AuditEntry {
            prev_hash: self.last_hash.clone(),
            timestamp: chrono::Utc::now().timestamp(),
            action: action.to_string(),
            user_id: "system".to_string(), // In real app, get generic identity
            resource_id: resource.to_string(),
        };

        // Calculate hash of current entry including previous hash (Merkle chain)
        let mut hasher = Hasher::new();
        hasher.update(entry.prev_hash.as_bytes());
        hasher.update(entry.action.as_bytes());
        hasher.update(entry.resource_id.as_bytes());
        hasher.update(&entry.timestamp.to_le_bytes()); // Use consistent endianness
        
        self.last_hash = hasher.finalize().to_hex().to_string();
        
        entry
    }
    
    pub fn get_head(&self) -> &str {
        &self.last_hash
    }
}
