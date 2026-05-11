from typing import Any, Dict, List, Callable
from PIL import Image

from aegis.core.image_object import ImageObject


class OperationRegistry:
    _operations: Dict[str, Callable] = {}

    @classmethod
    def register(cls, name: str):
        def decorator(func: Callable):
            cls._operations[name] = func
            return func
        return decorator

    @classmethod
    def get(cls, name: str) -> Callable:
        return cls._operations[name]


class PipelineEngine:
    def __init__(self):
        self._steps: List[Dict[str, Any]] = []

    def add_step(self, operation: str, **kwargs):
        self._steps.append({"operation": operation, "kwargs": kwargs})

    def execute(self, obj: ImageObject) -> ImageObject:
        current = obj
        for step in self._steps:
            op_name = step["operation"]
            op_func = OperationRegistry.get(op_name)
            current = current.apply(op_name, op_func, **step["kwargs"])
        return current
