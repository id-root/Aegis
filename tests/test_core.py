import pytest
import os
from PIL import Image
from aegis.core.image_object import ImageObject
from aegis.core.pipeline import PipelineEngine, OperationRegistry
from aegis.core.hashing import generate_crypto_hash

# Register dummy operation for testing
@OperationRegistry.register("dummy_op")
def dummy_op(image: Image.Image, value: int) -> Image.Image:
    # Just return a new Image to simulate an operation
    return image.copy()

@pytest.fixture
def sample_image(tmp_path):
    img = Image.new('RGB', (100, 100), color='red')
    path = tmp_path / "sample.jpg"
    img.save(path)
    return str(path)

def test_image_object_immutability(sample_image):
    obj = ImageObject.from_file(sample_image)
    initial_hash = obj.crypto_hash
    
    new_obj = obj.apply("dummy_op", OperationRegistry.get("dummy_op"), value=42)
    
    assert new_obj is not obj
    # Content is same, but technically the object instance is different. 
    # The history/audit log will differ.
    assert len(new_obj.audit_log.entries) == 1
    assert len(obj.audit_log.entries) == 0

def test_pipeline_engine(sample_image):
    engine = PipelineEngine()
    engine.add_step("dummy_op", value=10)
    engine.add_step("dummy_op", value=20)
    
    obj = ImageObject.from_file(sample_image)
    final_obj = engine.execute(obj)
    
    assert len(final_obj.audit_log.entries) == 2
    assert final_obj.audit_log.entries[0].details["value"] == 10
    assert final_obj.audit_log.entries[1].details["value"] == 20
