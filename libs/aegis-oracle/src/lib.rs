pub mod deepfake;
pub mod inference;

pub use deepfake::DeepfakeScanner;
pub use inference::InferenceEngine;

pub mod model;
pub use model::run_inference;
