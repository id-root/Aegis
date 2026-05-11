import os
import random
import secrets

def secure_shred(file_path: str, passes: int = 3) -> bool:
    """
    Securely overwrites a file before deletion to prevent forensic recovery.
    
    Implements a simplified DoD 5220.22-M style 3-pass overwrite:
    Pass 1: Overwrite with zeros (0x00)
    Pass 2: Overwrite with ones (0xFF)
    Pass 3: Overwrite with random data
    
    Args:
        file_path: The path to the file to shred.
        passes: Number of passes (default 3).
        
    Returns:
        True if successful, False otherwise.
    """
    if not os.path.exists(file_path):
        return False
        
    try:
        file_size = os.path.getsize(file_path)
        
        with open(file_path, "ba+", buffering=0) as f:
            for p in range(passes):
                f.seek(0)
                if p == 0:
                    # Pass 1: Zeros
                    data = b'\x00' * 4096
                elif p == 1:
                    # Pass 2: Ones
                    data = b'\xff' * 4096
                else:
                    # Pass 3: Random
                    data = secrets.token_bytes(4096)
                
                written = 0
                while written < file_size:
                    chunk_size = min(4096, file_size - written)
                    f.write(data[:chunk_size])
                    written += chunk_size
                    
                # Force write to disk
                os.fsync(f.fileno())
                
        # Rename file to obscure original name before unlinking
        dir_name = os.path.dirname(file_path)
        random_name = os.path.join(dir_name, secrets.token_hex(8) + ".tmp")
        os.rename(file_path, random_name)
        
        # Finally delete it
        os.remove(random_name)
        return True
        
    except Exception as e:
        raise RuntimeError(f"Secure shredding failed: {e}")
