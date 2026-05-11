"""
Metadata Covert Channel — GPS, ICC Profile & XMP Namespace Steganography

Three independent metadata-based hiding techniques:

1. **GPS Sub-Arcsecond Encoding**
   Encodes payload bits in the fractional parts of GPS coordinates.
   GPS has ~1m precision; sub-arcsecond digits (millimetre precision)
   are invisible to humans but can carry significant data.

2. **ICC Profile Embedding**
   Injects payload into a custom ICC profile private tag, disguised
   as a calibration data block.  Most image viewers ignore unknown
   ICC tags entirely.

3. **XMP Custom Namespace**
   Creates a valid XMP metadata block with a custom namespace containing
   the payload encoded as base64 in XML attributes.  Appears as
   legitimate software metadata.

All techniques leave the actual pixel data completely untouched.
"""

import struct
import base64
import hashlib
import json
from PIL import Image
from PIL.ExifTags import Base as ExifBase
import piexif
from typing import Optional


# ═══════════════════════════════════════════════════════════════════════════
#  GPS Sub-Arcsecond Channel
# ═══════════════════════════════════════════════════════════════════════════

def _bytes_to_gps_coords(payload: bytes) -> list:
    """
    Encode bytes into GPS coordinate pairs.
    
    Each byte pair → one coordinate with sub-arcsecond precision.
    Latitude range: -90 to 90, Longitude range: -180 to 180.
    We use the fractional seconds (6 decimal places) to encode data.
    """
    coords = []
    # Pack length header
    length_bytes = struct.pack("<I", len(payload))
    data = length_bytes + payload
    
    # Each coordinate pair stores 4 bytes (2 in lat fractional, 2 in lon fractional)
    for i in range(0, len(data), 4):
        chunk = data[i:i+4]
        if len(chunk) < 4:
            chunk = chunk + b'\x00' * (4 - len(chunk))
        
        # Encode into sub-arcsecond portions
        lat_frac = struct.unpack("<H", chunk[0:2])[0]
        lon_frac = struct.unpack("<H", chunk[2:4])[0]
        
        # Base coordinates (looks like a real location)
        # Using coordinates near tech hubs for plausibility
        lat = 37.0 + (lat_frac / 100000.0)  # ~37°N (San Francisco area)
        lon = -122.0 + (lon_frac / 100000.0)  # ~122°W
        
        coords.append((lat, lon))
    
    return coords


def _gps_coords_to_bytes(coords: list) -> bytes:
    """Decode GPS coordinate pairs back to bytes."""
    data = b""
    
    for lat, lon in coords:
        lat_frac = int(round((lat - 37.0) * 100000))
        lon_frac = int(round((lon + 122.0) * 100000))
        
        lat_frac = max(0, min(65535, lat_frac))
        lon_frac = max(0, min(65535, lon_frac))
        
        data += struct.pack("<H", lat_frac)
        data += struct.pack("<H", lon_frac)
    
    if len(data) < 4:
        return b""
    
    payload_len = struct.unpack("<I", data[:4])[0]
    if payload_len > len(data) - 4 or payload_len > 10 * 1024 * 1024:
        return b""
    
    return data[4:4 + payload_len]


def _float_to_rational(value: float) -> tuple:
    """Convert float to EXIF rational (numerator, denominator)."""
    # Use high precision denominator
    denom = 10000000
    numer = int(abs(value) * denom)
    return (numer, denom)


def _degrees_to_dms(decimal_degrees: float) -> tuple:
    """Convert decimal degrees to (degrees, minutes, seconds) rationals."""
    d = abs(decimal_degrees)
    degrees = int(d)
    minutes = int((d - degrees) * 60)
    seconds = (d - degrees - minutes / 60.0) * 3600.0
    
    return (
        (degrees, 1),
        (minutes, 1),
        (int(seconds * 10000), 10000)
    )


def embed_gps_channel(image_path: str, output_path: str,
                      payload: bytes) -> None:
    """
    Embed payload in GPS EXIF coordinates.
    
    The image's GPS metadata is modified to contain the payload in
    sub-arcsecond precision fields.  Maximum capacity depends on
    the number of coordinate pairs we store (typically ~252 bytes
    using multiple GPS tags).
    """
    if len(payload) > 252:
        raise ValueError(
            f"GPS channel capacity: ~252 bytes. Payload: {len(payload)} bytes. "
            "Use a different channel for larger payloads."
        )
    
    img = Image.open(image_path)
    
    # Get or create EXIF data
    try:
        exif_dict = piexif.load(img.info.get("exif", b""))
    except Exception:
        exif_dict = {"0th": {}, "Exif": {}, "GPS": {}, "1st": {}}
    
    coords = _bytes_to_gps_coords(payload)
    
    if len(coords) > 0:
        lat, lon = coords[0]
        
        # Primary GPS coordinates
        lat_ref = b"N" if lat >= 0 else b"S"
        lon_ref = b"W" if lon < 0 else b"E"
        
        exif_dict["GPS"][piexif.GPSIFD.GPSLatitudeRef] = lat_ref
        exif_dict["GPS"][piexif.GPSIFD.GPSLatitude] = _degrees_to_dms(lat)
        exif_dict["GPS"][piexif.GPSIFD.GPSLongitudeRef] = lon_ref
        exif_dict["GPS"][piexif.GPSIFD.GPSLongitude] = _degrees_to_dms(abs(lon))
    
    # Store additional coordinates in GPS processing method (UserComment-like)
    # Encode all coordinates as a JSON string in the GPS processing method field
    coord_data = json.dumps(coords).encode('utf-8')
    
    # Use GPS ProcessingMethod to store the full coordinate array
    exif_dict["GPS"][piexif.GPSIFD.GPSProcessingMethod] = (
        b"ASCII\x00\x00\x00" + base64.b64encode(coord_data)
    )
    
    exif_bytes = piexif.dump(exif_dict)
    img.save(output_path, exif=exif_bytes)


def extract_gps_channel(image_path: str) -> bytes:
    """
    Extract payload from GPS EXIF coordinates.
    """
    img = Image.open(image_path)
    
    try:
        exif_dict = piexif.load(img.info.get("exif", b""))
    except Exception:
        return b""
    
    gps = exif_dict.get("GPS", {})
    
    # Try to read from ProcessingMethod first (full data)
    proc_method = gps.get(piexif.GPSIFD.GPSProcessingMethod, b"")
    if proc_method and isinstance(proc_method, bytes):
        # Strip the charset header
        if b"ASCII\x00\x00\x00" in proc_method:
            b64_data = proc_method.split(b"ASCII\x00\x00\x00", 1)[1]
        else:
            b64_data = proc_method
        
        try:
            coord_data = base64.b64decode(b64_data)
            coords = json.loads(coord_data.decode('utf-8'))
            return _gps_coords_to_bytes(coords)
        except Exception:
            pass
    
    return b""


# ═══════════════════════════════════════════════════════════════════════════
#  ICC Profile Covert Channel
# ═══════════════════════════════════════════════════════════════════════════

def _build_icc_with_payload(payload: bytes) -> bytes:
    """
    Build a minimal valid ICC profile with payload hidden in a private tag.
    
    The payload is stored in a 'mluc' (multi-localized Unicode) tag with
    tag signature 'aegs' (a private/vendor tag).
    """
    # Minimal ICC v2.1 profile structure
    # Profile header (128 bytes) + tag table + tags
    
    payload_with_header = struct.pack("<I", len(payload)) + payload
    
    # We'll embed in a simple custom profile
    # Header fields
    profile_size = 128 + 4 + 12 + len(payload_with_header) + 128  # approximate
    
    header = bytearray(128)
    struct.pack_into(">I", header, 0, profile_size)  # Profile size
    header[4:8] = b"aegs"  # Preferred CMM
    header[8:12] = struct.pack(">I", 0x02100000)  # Version 2.1
    header[12:16] = b"mntr"  # Device class: Monitor
    header[16:20] = b"RGB "  # Colour space
    header[20:24] = b"XYZ "  # PCS
    header[36:40] = b"acsp"  # Profile file signature
    header[40:44] = b"APPL"  # Primary platform
    header[64:68] = b"aegs"  # Creator
    
    # Tag table: 1 tag
    tag_count = struct.pack(">I", 1)
    
    # Tag entry: signature, offset, size
    tag_offset = 128 + 4 + 12  # header + tag_count + 1 tag entry
    tag_entry = b"desc" + struct.pack(">II", tag_offset, len(payload_with_header))
    
    # Assemble
    profile = bytes(header) + tag_count + tag_entry + payload_with_header
    
    # Pad to 4-byte alignment
    while len(profile) % 4 != 0:
        profile += b'\x00'
    
    # Update profile size
    profile = struct.pack(">I", len(profile)) + profile[4:]
    
    return profile


def _extract_from_icc(icc_data: bytes) -> bytes:
    """Extract payload from custom ICC profile."""
    if len(icc_data) < 132:
        return b""
    
    # Read tag count
    tag_count = struct.unpack(">I", icc_data[128:132])[0]
    
    if tag_count < 1 or tag_count > 100:
        return b""
    
    # Read first tag
    offset = 132
    for _ in range(tag_count):
        if offset + 12 > len(icc_data):
            break
        
        sig = icc_data[offset:offset+4]
        tag_offset = struct.unpack(">I", icc_data[offset+4:offset+8])[0]
        tag_size = struct.unpack(">I", icc_data[offset+8:offset+12])[0]
        
        if tag_offset + 4 <= len(icc_data):
            tag_data = icc_data[tag_offset:tag_offset + tag_size]
            if len(tag_data) >= 4:
                payload_len = struct.unpack("<I", tag_data[:4])[0]
                if payload_len <= tag_size - 4 and payload_len < 10 * 1024 * 1024:
                    return tag_data[4:4 + payload_len]
        
        offset += 12
    
    return b""


def embed_icc_channel(image_path: str, output_path: str,
                      payload: bytes) -> None:
    """
    Embed payload in a custom ICC colour profile.
    
    The profile appears as legitimate colour management data but contains
    the payload in a private tag.  Most image viewers/editors will preserve
    ICC profiles when saving.
    """
    img = Image.open(image_path)
    
    icc_profile = _build_icc_with_payload(payload)
    
    # Save with ICC profile
    img.save(output_path, icc_profile=icc_profile)


def extract_icc_channel(image_path: str) -> bytes:
    """Extract payload from ICC profile."""
    img = Image.open(image_path)
    
    icc_data = img.info.get("icc_profile", b"")
    if not icc_data:
        return b""
    
    return _extract_from_icc(icc_data)


# ═══════════════════════════════════════════════════════════════════════════
#  XMP Custom Namespace Channel
# ═══════════════════════════════════════════════════════════════════════════

def embed_xmp_channel(image_path: str, output_path: str,
                      payload: bytes) -> None:
    """
    Embed payload in XMP metadata using a custom namespace.
    
    Creates valid XMP-structured XML that looks like legitimate
    software metadata.
    """
    img = Image.open(image_path)
    
    # Encode payload as base64
    encoded = base64.b64encode(payload).decode('ascii')
    
    # Build XMP packet that looks like legitimate colour calibration data
    xmp_str = f"""<?xpacket begin="\xef\xbb\xbf" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
  <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
    <rdf:Description rdf:about=""
      xmlns:aegis="http://ns.aegis.security/calibration/1.0/"
      aegis:CalibrationVersion="2.1.0"
      aegis:CalibrationProfile="sRGB-D65-Gamma2.2"
      aegis:CalibrationData="{encoded}"
      aegis:CalibrationTimestamp="2025-01-15T10:30:00Z"
      aegis:DeviceModel="ColorMunki-Display"/>
  </rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>"""
    
    # Try to inject into EXIF
    try:
        exif_dict = piexif.load(img.info.get("exif", b""))
    except Exception:
        exif_dict = {"0th": {}, "Exif": {}, "GPS": {}, "1st": {}}
    
    # Store XMP in EXIF UserComment
    xmp_bytes = xmp_str.encode('utf-8')
    exif_dict["Exif"][piexif.ExifIFD.UserComment] = (
        b"ASCII\x00\x00\x00" + xmp_bytes
    )
    
    exif_bytes = piexif.dump(exif_dict)
    img.save(output_path, exif=exif_bytes)


def extract_xmp_channel(image_path: str) -> bytes:
    """Extract payload from XMP custom namespace."""
    img = Image.open(image_path)
    
    try:
        exif_dict = piexif.load(img.info.get("exif", b""))
    except Exception:
        return b""
    
    user_comment = exif_dict.get("Exif", {}).get(piexif.ExifIFD.UserComment, b"")
    
    if not user_comment:
        return b""
    
    # Strip charset header
    if isinstance(user_comment, bytes):
        if b"ASCII\x00\x00\x00" in user_comment:
            xmp_str = user_comment.split(b"ASCII\x00\x00\x00", 1)[1].decode('utf-8', errors='ignore')
        else:
            xmp_str = user_comment.decode('utf-8', errors='ignore')
    else:
        xmp_str = str(user_comment)
    
    # Parse the CalibrationData attribute
    import re
    match = re.search(r'aegis:CalibrationData="([A-Za-z0-9+/=]+)"', xmp_str)
    if match:
        try:
            return base64.b64decode(match.group(1))
        except Exception:
            pass
    
    return b""
