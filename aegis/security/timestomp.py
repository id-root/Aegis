import os
import shutil

def clone_timestamps(reference_file: str, target_file: str) -> bool:
    """
    Clones the Access (atime) and Modified (mtime) timestamps from a reference file
    to a target file.
    
    This is an anti-forensics technique (timestomping) used to make a newly created 
    or modified file blend in with existing files in a directory timeline.
    
    Args:
        reference_file: Path to the file whose timestamps will be copied.
        target_file: Path to the file whose timestamps will be modified.
        
    Returns:
        True if successful, False otherwise.
    """
    if not os.path.exists(reference_file):
        raise FileNotFoundError(f"Reference file not found: {reference_file}")
    if not os.path.exists(target_file):
        raise FileNotFoundError(f"Target file not found: {target_file}")
        
    try:
        # Get stat of reference file
        stat_info = os.stat(reference_file)
        
        # Apply atime and mtime to target file
        os.utime(target_file, (stat_info.st_atime, stat_info.st_mtime))
        return True
    except Exception as e:
        raise RuntimeError(f"Timestomping failed: {e}")
