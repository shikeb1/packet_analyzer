import struct

def extract_sni_from_tls(payload):
    """Extract SNI from TLS Client Hello."""
    if len(payload) < 5:
        return None
    if payload[0] != 0x16:
        return None
    if len(payload) < 6 or payload[5] != 0x01:
        return None
    
    offset = 5 + 4   # record header + handshake header
    if offset + 2 > len(payload):
        return None
    
    offset += 2  # version
    offset += 32  # random
    if offset >= len(payload):
        return None
    
    session_id_len = payload[offset]
    offset += 1 + session_id_len
    if offset + 2 > len(payload):
        return None
    
    cipher_len = struct.unpack('>H', payload[offset:offset+2])[0]
    offset += 2 + cipher_len
    if offset + 1 > len(payload):
        return None
    
    comp_len = payload[offset]
    offset += 1 + comp_len
    if offset + 2 > len(payload):
        return None
    
    ext_len = struct.unpack('>H', payload[offset:offset+2])[0]
    offset += 2
    ext_end = offset + ext_len
    if ext_end > len(payload):
        return None
    
    while offset + 4 <= ext_end:
        ext_type = struct.unpack('>H', payload[offset:offset+2])[0]
        ext_data_len = struct.unpack('>H', payload[offset+2:offset+4])[0]
        offset += 4
        if ext_type == 0x0000:  # SNI
            if offset + 2 > ext_end:
                break
            sni_list_len = struct.unpack('>H', payload[offset:offset+2])[0]
            offset += 2
            if offset + 3 > ext_end:
                break
            sni_type = payload[offset]
            sni_len = struct.unpack('>H', payload[offset+1:offset+3])[0]
            offset += 3
            if sni_type == 0x00:  # hostname
                if offset + sni_len <= ext_end:
                    sni = payload[offset:offset+sni_len].decode('utf-8', errors='ignore')
                    return sni
        offset += ext_data_len
    return None

def extract_host_from_http(payload):
    """Extract Host header from HTTP request."""
    try:
        text = payload.decode('utf-8', errors='ignore')
        lines = text.split('\r\n')
        for line in lines:
            if line.lower().startswith('host:'):
                return line[5:].strip()
    except:
        pass
    return None