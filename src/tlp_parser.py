"""PCIe TLP Parser - Main module for parsing Transaction Layer Packets"""

import struct
from typing import Optional, List, Union, Dict, Any
from dataclasses import dataclass
from enum import Enum

from .tlp_types import TLPType, TLPFormat, CompletionStatus, MessageCode
from .utils import extract_field, bytes_to_dwords, hexdump


@dataclass
class TLPPacket:
    """Base class for TLP packets"""
    fmt: int
    tlp_type: int
    traffic_class: int
    length: int
    raw_data: bytes
    
    def __str__(self):
        return f"TLPPacket(type=0x{self.tlp_type:02X}, fmt={self.fmt}, len={self.length})"


@dataclass
class MemoryTransaction(TLPPacket):
    """Memory Read/Write Transaction"""
    address: int = 0
    requester_id: int = 0
    tag: int = 0
    first_be: int = 0
    last_be: int = 0
    data: bytes = b''
    
    def get_data(self) -> bytes:
        """Get transaction data"""
        return self.data


@dataclass
class IOTransaction(TLPPacket):
    """I/O Read/Write Transaction"""
    address: int = 0
    requester_id: int = 0
    tag: int = 0
    first_be: int = 0
    last_be: int = 0
    data: bytes = b''


@dataclass
class ConfigTransaction(TLPPacket):
    """Configuration Read/Write Transaction"""
    bus: int = 0
    device: int = 0
    function: int = 0
    register_offset: int = 0
    requester_id: int = 0
    tag: int = 0
    first_be: int = 0
    last_be: int = 0
    data: bytes = b''


@dataclass
class CompletionTransaction(TLPPacket):
    """Completion Packet"""
    status: int = 0
    byte_count: int = 0
    requester_id: int = 0
    tag: int = 0
    completer_id: int = 0
    lower_address: int = 0
    data: bytes = b''
    
    @property
    def status_name(self) -> str:
        """Get human-readable status"""
        status_names = {
            0: "Successful Completion",
            1: "Unsupported Request",
            2: "Configuration Request Retry",
            4: "Completer Abort"
        }
        return status_names.get(self.status, f"Unknown({self.status})")


@dataclass
class MessageTransaction(TLPPacket):
    """Message Packet"""
    message_code: int = 0
    requester_id: int = 0
    tag: int = 0
    data: bytes = b''
    
    @property
    def message_name(self) -> str:
        """Get human-readable message type"""
        msg_names = {
            0x00: "Unlock",
            0x01: "Assert_INTA",
            0x02: "Assert_INTB",
            0x03: "Assert_INTC",
            0x04: "Assert_INTD",
            0x05: "Deassert_INTA",
            0x06: "Deassert_INTB",
            0x07: "Deassert_INTC",
            0x08: "Deassert_INTD",
            0x10: "PM_Active_State_NAK",
            0x14: "PM_PME",
            0x20: "ERR_Correctable",
            0x21: "ERR_NonFatal",
            0x22: "ERR_Fatal",
            0x30: "WAKE",
        }
        return msg_names.get(self.message_code, f"Unknown(0x{self.message_code:02X})")


class TLPPacketAnalyzer:
    """Parse and analyze PCIe TLP packets"""
    
    def __init__(self, verbose: bool = False):
        """
        Initialize TLP Parser
        
        Args:
            verbose: Enable verbose output
        """
        self.verbose = verbose
        self.packets_parsed = 0
        self.packet_stats = {
            'memory_read': 0,
            'memory_write': 0,
            'io_read': 0,
            'io_write': 0,
            'config_read': 0,
            'config_write': 0,
            'completion': 0,
            'message': 0,
            'unknown': 0
        }
    
    def parse_tlp(
        self,
        data: bytes,
        verbose: bool = False
    ) -> Optional[Union[MemoryTransaction, IOTransaction, ConfigTransaction,
                       CompletionTransaction, MessageTransaction, TLPPacket]]:
        """
        Parse a single TLP packet
        
        Args:
            data: Raw packet bytes
            verbose: Override verbose setting for this parse
            
        Returns:
            Parsed TLP packet object or None if parsing fails
        """
        verbose = verbose or self.verbose
        
        if len(data) < 12:
            if verbose:
                print("ERROR: Packet too short")
            return None
        
        # Convert to DWORDs
        dwords = bytes_to_dwords(data)
        if len(dwords) < 3:
            return None
        
        # Parse header fields from DW0
        dw0 = dwords[0]
        fmt = extract_field(dw0, 30, 2)
        tlp_type = extract_field(dw0, 25, 5)
        tc = extract_field(dw0, 20, 3)
        td = extract_field(dw0, 18, 1)
        ep = extract_field(dw0, 17, 1)
        
        # Determine packet format
        has_data = fmt in [2, 3]
        header_size = 16 if fmt in [1, 3] else 12
        
        if len(data) < header_size:
            if verbose:
                print(f"ERROR: Incomplete header for format {fmt}")
            return None
        
        # Extract length
        length = extract_field(dwords[2], 0, 10)
        if fmt in [1, 3]:
            length = extract_field(dwords[3], 0, 10)
        
        if verbose:
            print(f"Format: {fmt}, Type: 0x{tlp_type:02X}, TC: {tc}, Length: {length}")
        
        # Parse based on type
        if tlp_type in [0x00]:  # Memory Read/Write
            return self._parse_memory_transaction(
                dwords, data, fmt, tlp_type, tc, has_data, verbose
            )
        elif tlp_type in [0x02, 0x03]:  # I/O Read/Write
            return self._parse_io_transaction(
                dwords, data, fmt, tlp_type, tc, has_data, verbose
            )
        elif tlp_type in [0x04, 0x05]:  # Config Read/Write
            return self._parse_config_transaction(
                dwords, data, fmt, tlp_type, tc, has_data, verbose
            )
        elif tlp_type in [0x0A, 0x0B, 0x0C, 0x0D]:  # Completion
            return self._parse_completion_transaction(
                dwords, data, fmt, tlp_type, tc, has_data, verbose
            )
        elif tlp_type in [0x10, 0x11]:  # Message
            return self._parse_message_transaction(
                dwords, data, fmt, tlp_type, tc, has_data, verbose
            )
        else:
            if verbose:
                print(f"Unknown TLP type: 0x{tlp_type:02X}")
            self.packet_stats['unknown'] += 1
            return TLPPacket(fmt, tlp_type, tc, length, data)
    
    def parse_tlp_stream(self, data: bytes) -> List[TLPPacket]:
        """
        Parse multiple concatenated TLP packets
        
        Args:
            data: Raw stream bytes
            
        Returns:
            List of parsed packets
        """
        packets = []
        offset = 0
        
        while offset < len(data):
            # Parse one packet
            packet_data = data[offset:]
            packet = self.parse_tlp(packet_data)
            
            if packet is None:
                break
            
            packets.append(packet)
            
            # Calculate packet size
            fmt = extract_field(int.from_bytes(packet_data[0:4], 'big'), 30, 2)
            header_size = 16 if fmt in [1, 3] else 12
            
            # Extract length
            dw2 = int.from_bytes(packet_data[8:12], 'big')
            length = extract_field(dw2, 0, 10)
            
            if fmt in [1, 3]:
                dw3 = int.from_bytes(packet_data[12:16], 'big')
                length = extract_field(dw3, 0, 10)
            
            payload_size = length * 4 if length > 0 else 0
            packet_size = header_size + payload_size
            
            offset += packet_size
        
        self.packets_parsed += len(packets)
        return packets
    
    def print_statistics(self):
        """Print packet statistics"""
        print("\n" + "="*50)
        print("TLP PACKET STATISTICS")
        print("="*50)
        print(f"Total packets parsed: {self.packets_parsed}")
        print(f"Memory Read:     {self.packet_stats['memory_read']}")
        print(f"Memory Write:    {self.packet_stats['memory_write']}")
        print(f"I/O Read:        {self.packet_stats['io_read']}")
        print(f"I/O Write:       {self.packet_stats['io_write']}")
        print(f"Config Read:     {self.packet_stats['config_read']}")
        print(f"Config Write:    {self.packet_stats['config_write']}")
        print(f"Completion:      {self.packet_stats['completion']}")
        print(f"Message:         {self.packet_stats['message']}")
        print(f"Unknown:         {self.packet_stats['unknown']}")
        print("="*50)
    
    # ===== Private parsing methods =====
    
    def _parse_memory_transaction(
        self,
        dwords: List[int],
        data: bytes,
        fmt: int,
        tlp_type: int,
        tc: int,
        has_data: bool,
        verbose: bool
    ) -> MemoryTransaction:
        """Parse memory read/write transaction"""
        dw1 = dwords[1]
        requester_id = extract_field(dw1, 16, 16)
        tag = extract_field(dw1, 8, 8)
        first_be = extract_field(dw1, 0, 4)
        last_be = extract_field(dw1, 4, 4)
        
        # Extract length
        if fmt in [0, 2]:  # 3DW
            dw2 = dwords[2]
            address = (extract_field(dw2, 0, 32)) & 0xFFFFFC00
            length = extract_field(dw2, 0, 10)
        else:  # 4DW
            address = (dwords[2] << 32) | (dwords[3] & 0xFFFFFC00)
            length = extract_field(dwords[3], 0, 10)
        
        # Extract payload
        header_size = 16 if fmt in [1, 3] else 12
        payload_size = length * 4 if length > 0 else 0
        payload = data[header_size:header_size + payload_size]
        
        # Determine read vs write
        is_write = has_data
        stat_key = 'memory_write' if is_write else 'memory_read'
        self.packet_stats[stat_key] += 1
        
        if verbose:
            print(f"Memory {'Write' if is_write else 'Read'}: addr=0x{address:X}, len={length}, RID=0x{requester_id:04X}")
        
        return MemoryTransaction(
            fmt=fmt,
            tlp_type=tlp_type,
            traffic_class=tc,
            length=length,
            raw_data=data,
            address=address,
            requester_id=requester_id,
            tag=tag,
            first_be=first_be,
            last_be=last_be,
            data=payload
        )
    
    def _parse_io_transaction(
        self,
        dwords: List[int],
        data: bytes,
        fmt: int,
        tlp_type: int,
        tc: int,
        has_data: bool,
        verbose: bool
    ) -> IOTransaction:
        """Parse I/O read/write transaction"""
        dw1 = dwords[1]
        requester_id = extract_field(dw1, 16, 16)
        tag = extract_field(dw1, 8, 8)
        first_be = extract_field(dw1, 0, 4)
        last_be = extract_field(dw1, 4, 4)
        
        dw2 = dwords[2]
        address = extract_field(dw2, 0, 32) & 0xFFFFFFFF
        
        is_write = tlp_type == 0x03
        stat_key = 'io_write' if is_write else 'io_read'
        self.packet_stats[stat_key] += 1
        
        header_size = 16 if fmt in [1, 3] else 12
        payload = data[header_size:] if has_data else b''
        
        if verbose:
            print(f"I/O {'Write' if is_write else 'Read'}: addr=0x{address:X}")
        
        return IOTransaction(
            fmt=fmt,
            tlp_type=tlp_type,
            traffic_class=tc,
            length=1,
            raw_data=data,
            address=address,
            requester_id=requester_id,
            tag=tag,
            first_be=first_be,
            last_be=last_be,
            data=payload
        )
    
    def _parse_config_transaction(
        self,
        dwords: List[int],
        data: bytes,
        fmt: int,
        tlp_type: int,
        tc: int,
        has_data: bool,
        verbose: bool
    ) -> ConfigTransaction:
        """Parse configuration read/write transaction"""
        dw1 = dwords[1]
        requester_id = extract_field(dw1, 16, 16)
        tag = extract_field(dw1, 8, 8)
        first_be = extract_field(dw1, 0, 4)
        last_be = extract_field(dw1, 4, 4)
        
        dw2 = dwords[2]
        address = extract_field(dw2, 0, 32)
        bdf = (address >> 16) & 0xFFFF
        register_offset = address & 0xFFF
        
        bus = (bdf >> 8) & 0xFF
        device = (bdf >> 3) & 0x1F
        function = bdf & 0x7
        
        is_write = tlp_type == 0x05
        stat_key = 'config_write' if is_write else 'config_read'
        self.packet_stats[stat_key] += 1
        
        header_size = 16 if fmt in [1, 3] else 12
        payload = data[header_size:] if has_data else b''
        
        if verbose:
            print(f"Config {'Write' if is_write else 'Read'}: {bus:02X}:{device:02X}.{function} offset=0x{register_offset:03X}")
        
        return ConfigTransaction(
            fmt=fmt,
            tlp_type=tlp_type,
            traffic_class=tc,
            length=1,
            raw_data=data,
            bus=bus,
            device=device,
            function=function,
            register_offset=register_offset,
            requester_id=requester_id,
            tag=tag,
            first_be=first_be,
            last_be=last_be,
            data=payload
        )
    
    def _parse_completion_transaction(
        self,
        dwords: List[int],
        data: bytes,
        fmt: int,
        tlp_type: int,
        tc: int,
        has_data: bool,
        verbose: bool
    ) -> CompletionTransaction:
        """Parse completion packet"""
        dw1 = dwords[1]
        byte_count = extract_field(dw1, 16, 13)
        status = extract_field(dw1, 13, 3)
        
        dw2 = dwords[2]
        requester_id = extract_field(dw2, 16, 16)
        tag = extract_field(dw2, 8, 8)
        lower_address = extract_field(dw2, 0, 7)
        
        dw3 = dwords[3]
        completer_id = extract_field(dw3, 16, 16)
        length = extract_field(dw3, 0, 10)
        
        self.packet_stats['completion'] += 1
        
        header_size = 16
        payload_size = length * 4
        payload = data[header_size:header_size + payload_size]
        
        if verbose:
            status_names = {0: "SC", 1: "UR", 2: "CRS", 4: "CA"}
            print(f"Completion: Status={status_names.get(status, str(status))}, byte_count={byte_count}")
        
        return CompletionTransaction(
            fmt=fmt,
            tlp_type=tlp_type,
            traffic_class=tc,
            length=length,
            raw_data=data,
            status=status,
            byte_count=byte_count,
            requester_id=requester_id,
            tag=tag,
            completer_id=completer_id,
            lower_address=lower_address,
            data=payload
        )
    
    def _parse_message_transaction(
        self,
        dwords: List[int],
        data: bytes,
        fmt: int,
        tlp_type: int,
        tc: int,
        has_data: bool,
        verbose: bool
    ) -> MessageTransaction:
        """Parse message packet"""
        dw1 = dwords[1]
        requester_id = extract_field(dw1, 16, 16)
        tag = extract_field(dw1, 8, 8)
        message_code = extract_field(dw1, 0, 8)
        
        header_size = 16 if fmt in [1, 3] else 12
        payload = data[header_size:] if has_data else b''
        
        self.packet_stats['message'] += 1
        
        if verbose:
            print(f"Message: code=0x{message_code:02X}, RID=0x{requester_id:04X}")
        
        return MessageTransaction(
            fmt=fmt,
            tlp_type=tlp_type,
            traffic_class=tc,
            length=0,
            raw_data=data,
            message_code=message_code,
            requester_id=requester_id,
            tag=tag,
            data=payload
        )
