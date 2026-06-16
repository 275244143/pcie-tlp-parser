"""Utility Functions for PCIe TLP Parser"""

import struct
from typing import Optional


def hexdump(data: bytes, offset: int = 0, width: int = 16):
    """
    Print hex dump of data
    
    Args:
        data: Bytes to dump
        offset: Starting offset for display
        width: Number of bytes per line
    """
    for i in range(0, len(data), width):
        hex_part = ' '.join(f'{b:02X}' for b in data[i:i+width])
        ascii_part = ''.join(
            chr(b) if 32 <= b < 127 else '.' 
            for b in data[i:i+width]
        )
        print(f"{offset+i:08X}  {hex_part:<48}  {ascii_part}")


def bytes_to_dwords(data: bytes) -> list:
    """
    Convert bytes to list of DWORDs (32-bit big-endian integers)
    
    Args:
        data: Bytes to convert
        
    Returns:
        List of 32-bit integers
    """
    dwords = []
    for i in range(0, len(data), 4):
        if i + 4 <= len(data):
            dw = struct.unpack('>I', data[i:i+4])[0]
            dwords.append(dw)
    return dwords


def dwords_to_bytes(dwords: list) -> bytes:
    """
    Convert list of DWORDs to bytes
    
    Args:
        dwords: List of 32-bit integers
        
    Returns:
        Bytes representation
    """
    data = b''
    for dw in dwords:
        data += struct.pack('>I', dw & 0xFFFFFFFF)
    return data


def create_tlp_header(
    fmt: int,
    tlp_type: int,
    length_dw: int,
    traffic_class: int = 0,
    requester_id: int = 0,
    tag: int = 0
) -> bytes:
    """
    Create a basic TLP header
    
    Args:
        fmt: Format (0-3)
        tlp_type: Transaction type
        length_dw: Payload length in DWORDs
        traffic_class: Traffic class (0-7)
        requester_id: Requester bus/device/function
        tag: Transaction tag
        
    Returns:
        Header bytes (12 or 16 bytes depending on format)
    """
    # First DWORD: Format/Type, Traffic Class, Routing
    fmt_type = (fmt << 6) | tlp_type
    dw0 = (fmt_type << 24) | (traffic_class << 20)
    
    # Second DWORD: Tag, Command Type, Length
    dw1 = (tag << 24) | (length_dw & 0x3FF)
    
    # Third DWORD: Requester ID, etc.
    dw2 = (requester_id << 16) | 0x0000
    
    header = struct.pack('>III', dw0, dw1, dw2)
    
    # Add fourth DWORD if 4DW format
    if fmt in [1, 3]:
        dw3 = 0x00000000
        header += struct.pack('>I', dw3)
    
    return header


def create_tlp_packet(
    fmt: int,
    tlp_type: int,
    length_dw: int,
    data: bytes = b'',
    **kwargs
) -> bytes:
    """
    Create a complete TLP packet
    
    Args:
        fmt: Format (0-3)
        tlp_type: Transaction type
        length_dw: Payload length in DWORDs
        data: Payload data
        **kwargs: Additional header parameters
        
    Returns:
        Complete TLP packet bytes
    """
    header = create_tlp_header(fmt, tlp_type, length_dw, **kwargs)
    return header + data


def extract_field(dword: int, offset: int, width: int) -> int:
    """
    Extract a bitfield from a DWORD
    
    Args:
        dword: 32-bit value
        offset: Bit offset from right (LSB = 0)
        width: Field width in bits
        
    Returns:
        Extracted field value
    """
    mask = (1 << width) - 1
    return (dword >> offset) & mask


def insert_field(dword: int, value: int, offset: int, width: int) -> int:
    """
    Insert a bitfield into a DWORD
    
    Args:
        dword: Original 32-bit value
        value: Value to insert
        offset: Bit offset from right (LSB = 0)
        width: Field width in bits
        
    Returns:
        Modified DWORD
    """
    mask = (1 << width) - 1
    value &= mask
    dword &= ~(mask << offset)
    dword |= (value << offset)
    return dword


def format_bdf(bus: int, device: int, function: int) -> str:
    """
    Format Bus:Device.Function
    
    Args:
        bus: Bus number
        device: Device number
        function: Function number
        
    Returns:
        Formatted BDF string
    """
    return f"{bus:02X}:{device:02X}.{function}"


def parse_bdf(bdf_string: str) -> Optional[tuple]:
    """
    Parse Bus:Device.Function string
    
    Args:
        bdf_string: BDF string (e.g., "00:01.2")
        
    Returns:
        Tuple of (bus, device, function) or None if invalid
    """
    try:
        parts = bdf_string.split(':')
        if len(parts) != 2:
            return None
        bus = int(parts[0], 16)
        device_fn = parts[1].split('.')
        if len(device_fn) != 2:
            return None
        device = int(device_fn[0], 16)
        function = int(device_fn[1], 16)
        return (bus, device, function)
    except (ValueError, IndexError):
        return None
