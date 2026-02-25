import json
from typing import Any, Callable, Dict, List, Optional
from PIL import Image

from aegis.core.image_object import ImageObject

class OperationRegistry:
    """
    Registry for image processing operations. Maps string names to Callables.
    """
    _operations: Dict[str, Callable[[Image.Image, Any], Image.Image]] = {}

    @classmethod
    def register(cls, name: str):
        """Decorator to register an operation."""
        def decorator(func):
            cls._operations[name] = func
            return func
        return decorator

    @classmethod
    def get(cls, name: str) -> Callable:
        if name not in cls._operations:
            raise KeyError(f"Operation '{name}' not found in registry.")
        return cls._operations[name]

class PipelineEngine:
    """
    Deterministic processing pipeline for ImageObjects.
    """
    def __init__(self):
        self.steps: List[Dict[str, Any]] = []

    def add_step(self, operation_name: str, **kwargs):
        """Add an operation step to the pipeline."""
        # Validate existence
        OperationRegistry.get(operation_name)
        self.steps.append({
            "operation": operation_name,
            "params": kwargs
        })
        return self

    def execute(self, image_obj: ImageObject) -> ImageObject:
        """Execute the pipeline on an ImageObject."""
        current_obj = image_obj
        for step in self.steps:
            op_name = step["operation"]
            params = step["params"]
            op_func = OperationRegistry.get(op_name)
            current_obj = current_obj.apply(action_name=op_name, operation=op_func, **params)
        return current_obj
        
    def to_json(self) -> str:
        """Serialize pipeline to JSON."""
        return json.dumps({"steps": self.steps}, indent=2)
        
    @classmethod
    def from_json(cls, json_str: str) -> 'PipelineEngine':
        """Deserialize pipeline from JSON."""
        data = json.loads(json_str)
        engine = cls()
        engine.steps = data.get("steps", [])
        return engine
