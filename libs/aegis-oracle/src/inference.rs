use tract_onnx::prelude::*;
use std::path::Path;
use anyhow::Result;

type Runnable = SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>;

pub struct InferenceEngine {
    model: Runnable,
}

impl InferenceEngine {
    pub fn new<P: AsRef<Path>>(model_path: P) -> Result<Self> {
        let model = tract_onnx::onnx()
            .model_for_path(model_path.as_ref())?
            .into_optimized()?
            .into_runnable()?;
            
        Ok(Self { model })
    }

    pub fn run(&self, input_data: Vec<f32>, shape: Vec<usize>) -> Result<Vec<f32>> {
        let input = Tensor::from_shape(&shape, &input_data)?;
        let result = self.model.run(tvec!(input.into()))?;
        
        // Return first output as Vec<f32> (Simplified)
        let binding = result[0].to_array_view::<f32>()?;
        Ok(binding.as_slice().unwrap_or(&[]).to_vec())
    }
}
