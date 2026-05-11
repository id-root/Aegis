import os
from typing import Dict, Any

def analyze_binary(image_path: str) -> Dict[str, Any]:
    """
    Perform structural and binary analysis on the image.
    Currently focuses on EOF (End of File) anomaly detection and trailing data extraction.
    """
    result = {
        "eof_anomaly": False,
        "trailing_data_size": 0,
        "magic_bytes": "Unknown",
        "file_size": 0,
        "anomalies": []
    }
    
    try:
        if not os.path.exists(image_path):
            result["error"] = "File not found"
            return result
            
        file_size = os.path.getsize(image_path)
        result["file_size"] = file_size
        
        with open(image_path, 'rb') as f:
            data = f.read()
            
        if len(data) == 0:
            result["error"] = "Empty file"
            return result
            
        # Magic bytes check
        if data.startswith(b'\xff\xd8'):
            result["magic_bytes"] = "JPEG"
            # JPEG EOF is FF D9
            eof_marker = b'\xff\xd9'
            eof_index = data.rfind(eof_marker)
            
            if eof_index != -1:
                # Add 2 for the marker itself
                actual_end = eof_index + 2
                if actual_end < len(data):
                    trailing_size = len(data) - actual_end
                    result["eof_anomaly"] = True
                    result["trailing_data_size"] = trailing_size
                    result["anomalies"].append(f"Found {trailing_size} bytes of trailing data after JPEG EOF.")
            else:
                result["anomalies"].append("Missing standard JPEG EOF marker (FF D9).")
                
        elif data.startswith(b'\x89PNG\r\n\x1a\n'):
            result["magic_bytes"] = "PNG"
            # PNG EOF is IEND chunk: 00 00 00 00 49 45 4E 44 AE 42 60 82
            eof_marker = b'IEND\xaeB`\x82'
            eof_index = data.rfind(eof_marker)
            
            if eof_index != -1:
                actual_end = eof_index + len(eof_marker)
                if actual_end < len(data):
                    trailing_size = len(data) - actual_end
                    result["eof_anomaly"] = True
                    result["trailing_data_size"] = trailing_size
                    result["anomalies"].append(f"Found {trailing_size} bytes of trailing data after PNG IEND chunk.")
            else:
                 result["anomalies"].append("Missing standard PNG IEND chunk.")
        else:
            result["magic_bytes"] = "Unknown/Unsupported"
            result["anomalies"].append("File signature does not match supported formats (JPEG, PNG).")
            
    except Exception as e:
        result["error"] = str(e)
        
    return result

def extract_trailing_data(image_path: str, output_path: str) -> bool:
    """
    Extracts trailing data from an image and saves it to output_path.
    Returns True if data was extracted, False otherwise.
    """
    if not os.path.exists(image_path):
        return False
        
    with open(image_path, 'rb') as f:
        data = f.read()
        
    if data.startswith(b'\xff\xd8'):
        eof_marker = b'\xff\xd9'
        eof_index = data.rfind(eof_marker)
        if eof_index != -1:
            actual_end = eof_index + 2
            if actual_end < len(data):
                with open(output_path, 'wb') as out_f:
                    out_f.write(data[actual_end:])
                return True
                
    elif data.startswith(b'\x89PNG\r\n\x1a\n'):
        eof_marker = b'IEND\xaeB`\x82'
        eof_index = data.rfind(eof_marker)
        if eof_index != -1:
            actual_end = eof_index + len(eof_marker)
            if actual_end < len(data):
                with open(output_path, 'wb') as out_f:
                    out_f.write(data[actual_end:])
                return True
                
    return False
