pub mod crypto;
pub mod audit;
pub mod dms;

pub use audit::AuditLog;
pub use dms::DeadMansSwitch;
// pub use crypto::EncryptionEngine;
use sled::Db;
use anyhow::{Result, anyhow};
// use crypto::EncryptionEngine;

use std::path::Path;

pub struct Vault {
    _db: Db,
    // encryption: EncryptionEngine, // Keep separate for now or integrate with read/write
    audit: AuditLog,
}

impl Vault {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let db = sled::open(path).map_err(|e| anyhow!("Failed to open DB: {}", e))?;
        Ok(Vault {
            _db: db,
            audit: AuditLog::new(),
        })
    }

    pub fn init_new(path: &str) -> Result<()> {
        let _db = sled::open(path)?;
        println!("[VAULT] Initialized secure database at {}", path);
        Ok(())
    }
    
    pub fn log_action(&mut self, action: &str) -> String {
        let _entry = self.audit.append(action, "generic_resource");
        format!("Action logged. New Head: {}", self.audit.get_head())
    }
}
