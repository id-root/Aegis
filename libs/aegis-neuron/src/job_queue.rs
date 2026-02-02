use std::collections::BinaryHeap;
use std::cmp::Ordering;
use uuid::Uuid;

#[derive(Debug, Eq, PartialEq)]
pub struct ForensicJob {
    pub id: Uuid,
    pub priority: u8,
    pub file_path: String,
}

// Order jobs by priority (higher is better)
impl Ord for ForensicJob {
    fn cmp(&self, other: &Self) -> Ordering {
        self.priority.cmp(&other.priority)
    }
}

impl PartialOrd for ForensicJob {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

pub struct JobQueue {
    heap: BinaryHeap<ForensicJob>,
}

impl JobQueue {
    pub fn new() -> Self {
        JobQueue {
            heap: BinaryHeap::new(),
        }
    }

    pub fn push(&mut self, job: ForensicJob) {
        self.heap.push(job);
    }

    pub fn pop(&mut self) -> Option<ForensicJob> {
        self.heap.pop()
    }
}
