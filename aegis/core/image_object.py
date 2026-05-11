import io
from copy import deepcopy
from typing import Any, Dict, Optional, Callable
from PIL import Image

from aegis.core.hashing import generate_crypto_hash, generate_perceptual_hash
from aegis.core.audit import AuditSystem

class ImageObject:
    """
    Immutable image representation with forensic tracking.
    When an operation is applied, a NEW ImageObject is returned.
    """
    def __init__(self, image: Image.Image, source_path: str = "memory", audit_log: Optional[AuditSystem] = None):
        self._image = image.copy()
        
        # Calculate initial hashes
        self._crypto_hash = self._calculate_current_crypto_hash()
        self._perceptual_hash = generate_perceptual_hash(self._image)
        
        self.source_path = source_path
        
        if audit_log is None:
            self.audit_log = AuditSystem(initial_source=source_path, initial_hash=self._crypto_hash)
        else:
            self.audit_log = audit_log

    @classmethod
    def from_file(cls, filepath: str) -> 'ImageObject':
        """Load an image from disk and initialize forensic tracking."""
        img = Image.open(filepath)
        # We need to eagerly load the pixel data before the file is closed, 
        # or just hold the image copy.
        img.load()
        return cls(image=img, source_path=filepath)

    @property
    def image(self) -> Image.Image:
        """Return a copy of the underlying image to prevent in-place modification."""
        return self._image.copy()

    @property
    def crypto_hash(self) -> str:
        return self._crypto_hash
        
    @property
    def perceptual_hash(self) -> str:
        return self._perceptual_hash

    def _calculate_current_crypto_hash(self) -> str:
        """Calculates cryptographic hash of the current image byte stream."""
        # Convert image to a stable byte representation (PNG) for hashing
        buf = io.BytesIO()
        # Save without any volatile metadata ideally, but this is a base implementation
        self._image.save(buf, format="PNG")
        return generate_crypto_hash(buf.getvalue())

    def apply(self, action_name: str, operation: Callable[[Image.Image, Any], Image.Image], **kwargs) -> 'ImageObject':
        """
        Apply an operation to the image, returning a NEW ImageObject 
        with the updated audit log.
        """
        # 1. Capture initial state
        initial_hash = self._crypto_hash
        
        # 2. Perform operation on a copy of the image
        new_img = operation(self.image, **kwargs)
        
        # 3. Create a new Audit log based on the current one
        new_audit = self.audit_log.copy()
        
        # 4. Instantiate new ImageObject (this calculates the new initial values)
        new_obj = ImageObject(image=new_img, source_path=self.source_path, audit_log=new_audit)
        
        # 5. Log the operation in the new object's audit log
        new_obj.audit_log.log_operation(
            action=action_name,
            details=kwargs,
            initial_hash=initial_hash,
            result_hash=new_obj.crypto_hash
        )
        
        return new_obj

    def export(self, filepath: str, format: Optional[str] = None):
        """Save the image to disk."""
        self._image.save(filepath, format=format)
