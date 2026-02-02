use std::path::{Path, PathBuf};
use std::fs;
use chrono::{DateTime, Utc, Duration};
use serde::{Serialize, Deserialize};
use anyhow::{Result, anyhow, Context};

#[derive(Serialize, Deserialize)]
struct SwitchState {
    last_checkin: DateTime<Utc>,
    timeout_hours: i64,
}

pub struct DeadMansSwitch {
    path: PathBuf,
}

impl DeadMansSwitch {
    pub fn new<P: AsRef<Path>>(storage_path: P) -> Self {
        Self { path: storage_path.as_ref().join("dms.lock") }
    }

    pub fn init(&self, hours: i64) -> Result<()> {
        let state = SwitchState {
            last_checkin: Utc::now(),
            timeout_hours: hours,
        };
        self.save(&state)
    }

    pub fn checkin(&self) -> Result<String> {
        let mut state = self.load()?;
        state.last_checkin = Utc::now();
        self.save(&state)?;
        Ok(format!("Check-in successful. Next deadline: {}", state.last_checkin + Duration::hours(state.timeout_hours)))
    }

    pub fn check_status(&self) -> Result<(bool, String)> {
        // Returns (triggered, status_message)
        let state = self.load()?;
        let deadline = state.last_checkin + Duration::hours(state.timeout_hours);
        let now = Utc::now();
        
        if now > deadline {
            Ok((true, "TRIGGERED: Deadline expired.".to_string()))
        } else {
            let remaining = deadline - now;
            Ok((false, format!("Active. Time remaining: {}h {}m", remaining.num_hours(), remaining.num_minutes() % 60)))
        }
    }

    fn save(&self, state: &SwitchState) -> Result<()> {
        // Create dir if missing
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(state)?;
        fs::write(&self.path, json).context("Failed to write DMS lockfile")?;
        Ok(())
    }

    fn load(&self) -> Result<SwitchState> {
        if !self.path.exists() {
            return Err(anyhow!("Dead Man's Switch not initialized."));
        }
        let data = fs::read_to_string(&self.path).context("Failed to read DMS lockfile")?;
        let state: SwitchState = serde_json::from_str(&data).context("Failed to parse DMS state")?;
        Ok(state)
    }
}
