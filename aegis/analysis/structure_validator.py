"""
Binary Structure Validator — PNG Chunk & JPEG Marker Scanner

Deep structural analysis for detecting steganographic covert channels
hidden in image container structures rather than pixel data.

PNG Analysis:
  - Validates every chunk's CRC32 checksum
  - Identifies non-standard/private chunks (potential data carriers)
  - Detects data after IEND (appended payload)
  - Checks for suspicious tEXt/zTXt/iTXt content
  - Validates IHDR parameters

JPEG Analysis:
  - Validates marker sequence (SOI → APP → SOF → SOS → EOI)
  - Detects non-standard APP markers (APP3-APP15 = suspicious)
  - Identifies data gaps between markers
  - Checks for multiple SOS segments (progressive JPEG vs. payload)
  - Detects data after EOI marker
"""

import struct
import zlib
from typing import Dict, Any, List, Optional


# ═══════════════════════════════════════════════════════════════════════════
#  PNG Chunk Analysis
# ═══════════════════════════════════════════════════════════════════════════

PNG_SIGNATURE = b'\x89PNG\r\n\x1a\n'

# Standard PNG chunk types
PNG_CRITICAL_CHUNKS = {'IHDR', 'PLTE', 'IDAT', 'IEND'}
PNG_ANCILLARY_STANDARD = {
    'cHRM', 'gAMA', 'iCCP', 'sBIT', 'sRGB',  # Colour
    'bKGD', 'hIST', 'tRNS',                    # Transparency
    'pHYs', 'sPLT',                             # Layout
    'tIME',                                      # Timestamp
    'tEXt', 'zTXt', 'iTXt',                     # Text
    'eXIf',                                      # EXIF (newer)
}

# Chunks commonly used for steganography
PNG_SUSPICIOUS_CHUNKS = {
    'tEXt': 'Uncompressed text — may contain encoded payload',
    'zTXt': 'Compressed text — may contain hidden data',
    'iTXt': 'International text — may contain encoded data',
    'eXIf': 'EXIF metadata — may contain hidden data in custom tags',
}


def _parse_png_chunks(data: bytes) -> List[Dict[str, Any]]:
    """Parse all PNG chunks from raw file bytes."""
    chunks = []
    offset = 8  # Skip PNG signature
    
    while offset < len(data):
        if offset + 8 > len(data):
            break
        
        length = struct.unpack(">I", data[offset:offset+4])[0]
        chunk_type = data[offset+4:offset+8].decode('ascii', errors='replace')
        
        if offset + 12 + length > len(data):
            chunks.append({
                'type': chunk_type,
                'offset': offset,
                'length': length,
                'error': 'Truncated chunk',
            })
            break
        
        chunk_data = data[offset+8:offset+8+length]
        stored_crc = struct.unpack(">I", data[offset+8+length:offset+12+length])[0]
        
        # Compute CRC32
        computed_crc = zlib.crc32(data[offset+4:offset+8] + chunk_data) & 0xFFFFFFFF
        
        chunk_info = {
            'type': chunk_type,
            'offset': offset,
            'length': length,
            'crc_valid': stored_crc == computed_crc,
            'stored_crc': f"0x{stored_crc:08X}",
            'computed_crc': f"0x{computed_crc:08X}",
        }
        
        # Extract text from tEXt chunks
        if chunk_type == 'tEXt':
            null_idx = chunk_data.find(b'\x00')
            if null_idx >= 0:
                keyword = chunk_data[:null_idx].decode('latin-1', errors='replace')
                text = chunk_data[null_idx+1:].decode('latin-1', errors='replace')
                chunk_info['keyword'] = keyword
                chunk_info['text_preview'] = text[:200]
        
        elif chunk_type == 'zTXt':
            null_idx = chunk_data.find(b'\x00')
            if null_idx >= 0:
                keyword = chunk_data[:null_idx].decode('latin-1', errors='replace')
                chunk_info['keyword'] = keyword
                try:
                    decompressed = zlib.decompress(chunk_data[null_idx+2:])
                    chunk_info['decompressed_size'] = len(decompressed)
                    chunk_info['text_preview'] = decompressed[:200].decode('latin-1', errors='replace')
                except Exception:
                    chunk_info['decompression_error'] = True
        
        elif chunk_type == 'iTXt':
            null_idx = chunk_data.find(b'\x00')
            if null_idx >= 0:
                keyword = chunk_data[:null_idx].decode('utf-8', errors='replace')
                chunk_info['keyword'] = keyword
        
        elif chunk_type == 'IHDR' and length >= 13:
            width = struct.unpack(">I", chunk_data[0:4])[0]
            height = struct.unpack(">I", chunk_data[4:8])[0]
            bit_depth = chunk_data[8]
            colour_type = chunk_data[9]
            compression = chunk_data[10]
            filter_method = chunk_data[11]
            interlace = chunk_data[12]
            chunk_info['ihdr'] = {
                'width': width, 'height': height,
                'bit_depth': bit_depth, 'colour_type': colour_type,
                'compression': compression, 'filter': filter_method,
                'interlace': interlace,
            }
        
        chunks.append(chunk_info)
        offset += 12 + length
        
        if chunk_type == 'IEND':
            break
    
    return chunks


def validate_png(file_path: str) -> Dict[str, Any]:
    """
    Full PNG structural validation and steganography detection.
    
    Returns
    -------
    dict with:
      - valid_signature : bool
      - chunks : list of chunk analysis dicts
      - anomalies : list of detected anomalies
      - suspicious_chunks : list of chunks that could carry hidden data
      - data_after_iend : bool
      - data_after_iend_size : int
      - overall_status : str
    """
    with open(file_path, 'rb') as f:
        data = f.read()
    
    result = {
        'valid_signature': False,
        'file_size': len(data),
        'chunks': [],
        'anomalies': [],
        'suspicious_chunks': [],
        'data_after_iend': False,
        'data_after_iend_size': 0,
        'overall_status': 'UNKNOWN',
    }
    
    # Check PNG signature
    if not data.startswith(PNG_SIGNATURE):
        result['anomalies'].append('Invalid PNG signature')
        result['overall_status'] = 'INVALID (not a valid PNG file)'
        return result
    
    result['valid_signature'] = True
    
    # Parse chunks
    chunks = _parse_png_chunks(data)
    result['chunks'] = chunks
    
    # Validate chunk ordering
    if chunks and chunks[0]['type'] != 'IHDR':
        result['anomalies'].append('First chunk is not IHDR')
    
    # Check for CRC errors
    for chunk in chunks:
        if not chunk.get('crc_valid', True):
            result['anomalies'].append(
                f"CRC mismatch in {chunk['type']} at offset {chunk['offset']}"
            )
    
    # Check for data after IEND
    iend_found = False
    iend_end_offset = 0
    for chunk in chunks:
        if chunk['type'] == 'IEND':
            iend_found = True
            iend_end_offset = chunk['offset'] + 12 + chunk['length']
            break
    
    if iend_found and iend_end_offset < len(data):
        trailing_size = len(data) - iend_end_offset
        result['data_after_iend'] = True
        result['data_after_iend_size'] = trailing_size
        result['anomalies'].append(
            f"DATA AFTER IEND: {trailing_size} bytes of trailing data detected"
        )
    
    # Identify suspicious chunks
    chunk_types_seen = set()
    for chunk in chunks:
        ct = chunk['type']
        chunk_types_seen.add(ct)
        
        if ct in PNG_SUSPICIOUS_CHUNKS:
            result['suspicious_chunks'].append({
                'type': ct,
                'reason': PNG_SUSPICIOUS_CHUNKS[ct],
                'offset': chunk['offset'],
                'length': chunk['length'],
                'details': {k: v for k, v in chunk.items() 
                          if k in ('keyword', 'text_preview', 'decompressed_size')},
            })
        
        # Private/unknown chunk types (lowercase first letter = ancillary private)
        if ct not in PNG_CRITICAL_CHUNKS and ct not in PNG_ANCILLARY_STANDARD:
            if ct[0].islower():
                result['anomalies'].append(
                    f"Private ancillary chunk '{ct}' at offset {chunk['offset']} — "
                    f"potential covert channel"
                )
            else:
                result['anomalies'].append(
                    f"Unknown critical chunk '{ct}' at offset {chunk['offset']}"
                )
    
    # Check for multiple IDAT chunks (normal but note the count)
    idat_count = sum(1 for c in chunks if c['type'] == 'IDAT')
    if idat_count > 1:
        pass  # Normal for large images
    
    # Score
    n_anomalies = len(result['anomalies'])
    n_suspicious = len(result['suspicious_chunks'])
    
    if n_anomalies > 3 or result['data_after_iend']:
        result['overall_status'] = 'SUSPICIOUS (multiple structural anomalies)'
    elif n_anomalies > 0 or n_suspicious > 2:
        result['overall_status'] = 'UNCERTAIN (minor structural anomalies)'
    else:
        result['overall_status'] = 'CLEAN (structure appears normal)'
    
    return result


# ═══════════════════════════════════════════════════════════════════════════
#  JPEG Marker Analysis
# ═══════════════════════════════════════════════════════════════════════════

# Standard JPEG markers
JPEG_MARKERS = {
    0xD8: ('SOI', 'Start of Image'),
    0xD9: ('EOI', 'End of Image'),
    0xDA: ('SOS', 'Start of Scan'),
    0xDB: ('DQT', 'Define Quantization Table'),
    0xC0: ('SOF0', 'Start of Frame (Baseline)'),
    0xC1: ('SOF1', 'Start of Frame (Extended Sequential)'),
    0xC2: ('SOF2', 'Start of Frame (Progressive)'),
    0xC4: ('DHT', 'Define Huffman Table'),
    0xDD: ('DRI', 'Define Restart Interval'),
    0xFE: ('COM', 'Comment'),
    0xE0: ('APP0', 'JFIF'),
    0xE1: ('APP1', 'EXIF/XMP'),
    0xE2: ('APP2', 'ICC Profile'),
    0xE3: ('APP3', 'Application Segment 3'),
    0xE4: ('APP4', 'Application Segment 4'),
    0xE5: ('APP5', 'Application Segment 5'),
    0xE6: ('APP6', 'Application Segment 6'),
    0xE7: ('APP7', 'Application Segment 7'),
    0xE8: ('APP8', 'Application Segment 8'),
    0xE9: ('APP9', 'Application Segment 9'),
    0xEA: ('APP10', 'Application Segment 10'),
    0xEB: ('APP11', 'Application Segment 11'),
    0xEC: ('APP12', 'Application Segment 12'),
    0xED: ('APP13', 'Photoshop/IPTC'),
    0xEE: ('APP14', 'Adobe'),
    0xEF: ('APP15', 'Application Segment 15'),
}

# APP markers commonly used (not suspicious)
JPEG_COMMON_APP = {0xE0, 0xE1, 0xE2, 0xED, 0xEE}


def _parse_jpeg_markers(data: bytes) -> List[Dict[str, Any]]:
    """Parse all JPEG markers from raw file bytes."""
    markers = []
    offset = 0
    
    while offset < len(data):
        if data[offset] != 0xFF:
            offset += 1
            continue
        
        if offset + 1 >= len(data):
            break
        
        marker_byte = data[offset + 1]
        
        # Skip padding bytes (0xFF)
        if marker_byte == 0xFF:
            offset += 1
            continue
        
        # Skip stuffed zeros (0xFF 0x00 in compressed data)
        if marker_byte == 0x00:
            offset += 2
            continue
        
        marker_id = marker_byte
        marker_info = JPEG_MARKERS.get(marker_id, (f'0x{marker_id:02X}', 'Unknown'))
        
        entry = {
            'marker': marker_info[0],
            'description': marker_info[1],
            'marker_byte': f'0xFF{marker_id:02X}',
            'offset': offset,
        }
        
        if marker_id in (0xD8, 0xD9):
            # SOI and EOI have no payload
            entry['length'] = 0
            markers.append(entry)
            offset += 2
            
            if marker_id == 0xD9:
                # Check for data after EOI
                if offset < len(data):
                    entry['data_after_eoi'] = len(data) - offset
                break
        elif marker_id == 0xDA:
            # SOS: length field + scan data until next marker
            if offset + 4 > len(data):
                break
            seg_length = struct.unpack(">H", data[offset+2:offset+4])[0]
            entry['length'] = seg_length
            
            # Find next marker (skip entropy-coded data)
            scan_start = offset + 2 + seg_length
            scan_end = scan_start
            while scan_end < len(data) - 1:
                if data[scan_end] == 0xFF and data[scan_end + 1] != 0x00:
                    if data[scan_end + 1] != 0xFF:
                        break
                scan_end += 1
            
            entry['scan_data_size'] = scan_end - scan_start
            markers.append(entry)
            offset = scan_end
        else:
            # Standard segment with length field
            if offset + 4 > len(data):
                break
            seg_length = struct.unpack(">H", data[offset+2:offset+4])[0]
            entry['length'] = seg_length
            
            # Extract content preview for APP/COM markers
            if 0xE0 <= marker_id <= 0xEF:
                seg_data = data[offset+4:offset+2+seg_length]
                if seg_data:
                    entry['content_preview'] = seg_data[:50].decode('ascii', errors='replace')
            elif marker_id == 0xFE:  # Comment
                seg_data = data[offset+4:offset+2+seg_length]
                entry['comment'] = seg_data.decode('utf-8', errors='replace')
            
            markers.append(entry)
            offset += 2 + seg_length
    
    return markers


def validate_jpeg(file_path: str) -> Dict[str, Any]:
    """
    Full JPEG structural validation and steganography detection.
    
    Returns
    -------
    dict with:
      - valid_signature : bool
      - markers : list of marker analysis dicts
      - anomalies : list of detected anomalies
      - suspicious_markers : list of unusual markers
      - data_after_eoi : bool
      - data_after_eoi_size : int
      - overall_status : str
    """
    with open(file_path, 'rb') as f:
        data = f.read()
    
    result = {
        'valid_signature': False,
        'file_size': len(data),
        'markers': [],
        'anomalies': [],
        'suspicious_markers': [],
        'data_after_eoi': False,
        'data_after_eoi_size': 0,
        'overall_status': 'UNKNOWN',
    }
    
    # Check JPEG signature (SOI marker)
    if not data.startswith(b'\xFF\xD8'):
        result['anomalies'].append('Invalid JPEG signature (missing SOI)')
        result['overall_status'] = 'INVALID (not a valid JPEG file)'
        return result
    
    result['valid_signature'] = True
    
    # Parse markers
    markers = _parse_jpeg_markers(data)
    result['markers'] = markers
    
    # Validate marker sequence
    marker_sequence = [m['marker'] for m in markers]
    
    if marker_sequence and marker_sequence[0] != 'SOI':
        result['anomalies'].append('First marker is not SOI')
    
    if marker_sequence and marker_sequence[-1] != 'EOI':
        result['anomalies'].append('Last marker is not EOI')
    
    # Count SOS segments
    sos_count = sum(1 for m in marker_sequence if m == 'SOS')
    if sos_count > 1:
        result['anomalies'].append(
            f'Multiple SOS segments ({sos_count}) — may indicate progressive JPEG or data hiding'
        )
    
    # Check for data after EOI
    for marker in markers:
        if marker['marker'] == 'EOI' and 'data_after_eoi' in marker:
            trailing = marker['data_after_eoi']
            result['data_after_eoi'] = True
            result['data_after_eoi_size'] = trailing
            result['anomalies'].append(
                f'DATA AFTER EOI: {trailing} bytes of trailing data detected'
            )
    
    # Check for unusual APP markers
    for marker in markers:
        marker_byte_str = marker.get('marker_byte', '')
        
        # Suspicious APP markers (APP3-APP12, APP15)
        if marker['marker'].startswith('APP'):
            try:
                app_num = int(marker['marker'][3:])
                if app_num not in (0, 1, 2, 13, 14):
                    result['suspicious_markers'].append({
                        'marker': marker['marker'],
                        'offset': marker['offset'],
                        'length': marker.get('length', 0),
                        'reason': f'Uncommon {marker["marker"]} segment — potential covert channel',
                        'content_preview': marker.get('content_preview', ''),
                    })
            except ValueError:
                pass
        
        # Comment markers can hide data
        if marker['marker'] == 'COM':
            result['suspicious_markers'].append({
                'marker': 'COM',
                'offset': marker['offset'],
                'length': marker.get('length', 0),
                'reason': 'JPEG comment — may contain hidden data',
                'comment': marker.get('comment', ''),
            })
    
    # Score
    n_anomalies = len(result['anomalies'])
    n_suspicious = len(result['suspicious_markers'])
    
    if n_anomalies > 2 or result['data_after_eoi']:
        result['overall_status'] = 'SUSPICIOUS (multiple structural anomalies)'
    elif n_anomalies > 0 or n_suspicious > 1:
        result['overall_status'] = 'UNCERTAIN (minor structural anomalies)'
    else:
        result['overall_status'] = 'CLEAN (structure appears normal)'
    
    return result


# ═══════════════════════════════════════════════════════════════════════════
#  Unified Structure Scanner
# ═══════════════════════════════════════════════════════════════════════════

def scan_structure(file_path: str) -> Dict[str, Any]:
    """
    Auto-detect file type and run the appropriate structural validator.
    
    Supports PNG and JPEG files.
    """
    with open(file_path, 'rb') as f:
        header = f.read(8)
    
    if header.startswith(PNG_SIGNATURE):
        return {'format': 'PNG', **validate_png(file_path)}
    elif header[:2] == b'\xFF\xD8':
        return {'format': 'JPEG', **validate_jpeg(file_path)}
    else:
        return {
            'format': 'UNKNOWN',
            'error': f'Unsupported format. Magic bytes: {header[:4].hex()}',
        }
