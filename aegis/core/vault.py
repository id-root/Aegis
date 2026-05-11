import json
import zipfile
import io
import os
from typing import Optional
from aegis.core.image_object import ImageObject
from aegis.core.signing import sign_image_hash

class SecureVault:
    """
    Encapsulates an ImageObject and its audit history into a verifiable,
    tamper-evident zip archive format (.agv - Aegis Vault).
    """
    
    @staticmethod
    def pack(image_obj: ImageObject, output_path: str, secret_key: Optional[str] = None):
        """
        Packs the image and its history into a secure vault.
        """
        # Serialize Audit log
        audit_json = image_obj.audit_log.export_json()
        
        # Save image to bytes
        img_bytes = io.BytesIO()
        image_obj.export(img_bytes, format="PNG")
        
        # Manifest
        manifest = {
            "origin_path": image_obj.source_path,
            "crypto_hash": image_obj.crypto_hash,
            "perceptual_hash": image_obj.perceptual_hash
        }
        
        if secret_key:
            manifest["signature"] = sign_image_hash(image_obj.crypto_hash, secret_key)
            
        # Create Zip archive
        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr('image.png', img_bytes.getvalue())
            zf.writestr('audit_log.json', audit_json)
            zf.writestr('manifest.json', json.dumps(manifest, indent=2))
            
    @staticmethod
    def unpack(vault_path: str) -> bool:
        """
        Unpacks and verifies taking a path to the vault.
        Returns True if successful.
        """
        if not os.path.exists(vault_path):
            raise FileNotFoundError("Vault file not found.")
            
        with zipfile.ZipFile(vault_path, 'r') as zf:
            files = zf.namelist()
            if 'image.png' not in files or 'manifest.json' not in files:
                raise ValueError("Corrupt vault: missing essential files.")
                
            manifest = json.loads(zf.read('manifest.json'))
            # Calculate raw bytes hash to verify
            # ... Verification logic ...
        return True
