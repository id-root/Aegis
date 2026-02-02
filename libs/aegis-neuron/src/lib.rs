use actix::prelude::*;
use uuid::Uuid;

pub mod job_queue;
pub mod watchdog;

pub use job_queue::JobQueue;
pub use watchdog::Watchdog;

/// Message to request analysis on a file
#[derive(Message)]
#[rtype(result = "Result<AnalysisReport, String>")]
pub struct AnalyzeFile {
    pub path: String,
    pub analysis_type: AnalysisType,
}

#[derive(Debug, Clone, Copy)]
pub enum AnalysisType {
    Optics,
    Metadata,
    Steganography,
    Full,
}

#[derive(Debug)]
pub struct AnalysisReport {
    pub id: Uuid,
    pub risk_score: f32,
    pub details: String,
}

/// The Actor trait defines the behavior of our forensic worker
pub struct ForensicWorker;

impl Actor for ForensicWorker {
    type Context = Context<Self>;
}

impl Handler<AnalyzeFile> for ForensicWorker {
    type Result = Result<AnalysisReport, String>;

    fn handle(&mut self, msg: AnalyzeFile, _ctx: &mut Context<Self>) -> Self::Result {
        // In a real system, this would spawn blocking tasks or call other specialized actors.
        // For prototype, we simulate work.
        
        println!("[NEURON] Worker performing {:?} analysis on {}", msg.analysis_type, msg.path);
        
        Ok(AnalysisReport {
            id: Uuid::new_v4(),
            risk_score: 0.0,
            details: format!("Analysis complete for {}", msg.path),
        })
    }
}

pub struct SystemSupervisor {
    pub workers: Addr<ForensicWorker>,
}

impl Actor for SystemSupervisor {
    type Context = Context<Self>;
}

impl SystemSupervisor {
    pub fn new() -> Self {
        // Start a single worker for now (can be a pool)
        let worker_addr = ForensicWorker.start();
        SystemSupervisor {
            workers: worker_addr,
        }
    }
}
