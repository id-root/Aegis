from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
from typing import Dict, Any
from datetime import datetime

def _convert_to_degrees(value) -> float:
    """Helper function to convert the GPS coordinates stored in the EXIF to degrees in float format"""
    d0, d1 = value[0] if isinstance(value[0], tuple) else (value[0], 1)
    m0, m1 = value[1] if isinstance(value[1], tuple) else (value[1], 1)
    s0, s1 = value[2] if isinstance(value[2], tuple) else (value[2], 1)

    d = float(d0) / float(d1)
    m = float(m0) / float(m1)
    s = float(s0) / float(s1)

    return d + (m / 60.0) + (s / 3600.0)

def extract_metadata(image_path: str) -> Dict[str, Any]:
    """
    Extracts explicit metadata (EXIF/IFD) from an image.
    Uses Pillow's getexif() method and resolves basic tags.
    """
    result = {"exif": {}, "gps": {}, "timeline": {}}
    
    try:
        with Image.open(image_path) as img:
            result["format"] = img.format
            result["mode"] = img.mode
            result["size"] = img.size
            
            exif_data = img.getexif()
            if not exif_data:
                return result
                
            # Process standard EXIF
            for tag_id, value in exif_data.items():
                tag_name = TAGS.get(tag_id, tag_id)
                if isinstance(value, bytes):
                    try:
                        value = value.decode("utf-8", errors="replace")
                    except:
                        value = "<binary_data>"
                result["exif"][str(tag_name)] = value
                
            # Access IFD metadata (for GPS and other deep tags)
            ifd = exif_data.get_ifd(0x8825) # GPS IFD
            if ifd:
                gps_info = {}
                for key, val in ifd.items():
                    decode = GPSTAGS.get(key, key)
                    gps_info[decode] = val
                    
                if "GPSLatitude" in gps_info and "GPSLongitude" in gps_info:
                    lat = _convert_to_degrees(gps_info["GPSLatitude"])
                    lon = _convert_to_degrees(gps_info["GPSLongitude"])
                    
                    if gps_info.get("GPSLatitudeRef") == "S": lat = -lat
                    if gps_info.get("GPSLongitudeRef") == "W": lon = -lon
                    
                    result["gps"]["latitude"] = lat
                    result["gps"]["longitude"] = lon
                    result["gps"]["google_maps_url"] = f"https://www.google.com/maps?q={lat},{lon}"
                    
            # Timeline Reconstruction
            dates = []
            if "DateTime" in result["exif"]: dates.append(("DateTime (Modify)", result["exif"]["DateTime"]))
            if "DateTimeOriginal" in result["exif"]: dates.append(("DateTimeOriginal", result["exif"]["DateTimeOriginal"]))
            if "DateTimeDigitized" in result["exif"]: dates.append(("DateTimeDigitized", result["exif"]["DateTimeDigitized"]))
            
            # Simple chronological sanity check
            if len(dates) > 1:
                result["timeline"]["dates_found"] = dates
                try:
                    parsed_dates = [datetime.strptime(d[1], "%Y:%m:%d %H:%M:%S") for d in dates if isinstance(d[1], str)]
                    if parsed_dates:
                        oldest = min(parsed_dates)
                        newest = max(parsed_dates)
                        diff = newest - oldest
                        if diff.total_seconds() > 0:
                            result["timeline"]["status"] = "OK"
                            result["timeline"]["span_seconds"] = diff.total_seconds()
                            
                            # If ModifyDate < CreateDate it's suspicious
                            if "DateTimeOriginal" in result["exif"] and "DateTime" in result["exif"]:
                                orig = datetime.strptime(result["exif"]["DateTimeOriginal"], "%Y:%m:%d %H:%M:%S")
                                mod = datetime.strptime(result["exif"]["DateTime"], "%Y:%m:%d %H:%M:%S")
                                if mod < orig:
                                    result["timeline"]["status"] = "SUSPICIOUS (Modified before created)"
                except ValueError:
                    result["timeline"]["status"] = "ERROR (Malformed Dates)"
                    
    except Exception as e:
        result["error"] = str(e)
    return result
