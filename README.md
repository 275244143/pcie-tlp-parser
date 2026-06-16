# PCIe TLP Parser

A comprehensive Python library for parsing and analyzing PCIe Transaction Layer Packets (TLP).

## Overview

This project provides tools to parse, analyze, and generate PCIe TLP packets. It supports various TLP types including:

- **Memory Transactions**: Read/Write operations
- **I/O Transactions**: I/O Read/Write
- **Configuration Transactions**: Config Read/Write
- **Completion Transactions**: Completion with/without data
- **Message Transactions**: PCIe messages

## Features

- ✅ Parse TLP headers (3DW and 4DW formats)
- ✅ Extract transaction-specific fields
- ✅ Support for multiple TLP types
- ✅ Stream parsing for multiple packets
- ✅ Packet statistics and analysis
- ✅ TLP packet creation utilities
- ✅ Hex dump and detailed packet inspection

## Installation

```bash
git clone https://github.com/275244143/pcie-tlp-parser.git
cd pcie-tlp-parser
pip install -r requirements.txt
```

## Quick Start

```python
from src.tlp_parser import TLPPacketAnalyzer, MemoryTransaction

# Create analyzer
analyzer = TLPPacketAnalyzer()

# Parse a TLP packet
tlp_data = b'\x60\x00\x00\x01\x00\x00\x00\x08\x00\x00\xF0\x00\xDEADBEEF'
packet = analyzer.parse_tlp(tlp_data, verbose=True)

# Access packet fields
if isinstance(packet, MemoryTransaction):
    print(f"Address: 0x{packet.address:08X}")
    print(f"Data: {packet.get_data().hex()}")
```

## Project Structure

```
pcie-tlp-parser/
├── README.md
├── requirements.txt
├── src/
│   ├── __init__.py
│   ├── tlp_parser.py          # Main parser module
│   ├── tlp_types.py           # TLP type definitions
│   └── utils.py               # Utility functions
├── tests/
│   ├── __init__.py
│   ├── test_parser.py         # Unit tests
│   └── test_packets.py        # Test packet definitions
├── examples/
│   ├── basic_parsing.py       # Basic usage example
│   ├── stream_analysis.py     # Stream parsing example
│   └── packet_creation.py     # Packet generation example
└── docs/
    ├── tlp_format.md          # TLP format documentation
    └── api_reference.md       # API reference
```

## TLP Types

### Format and Type Encoding

```
Format (2 bits):
  00: 3 DW Header, no data
  01: 4 DW Header, no data (legacy)
  10: 3 DW Header, with data
  11: 4 DW Header, with data

Type (5 bits):
  0x00: Memory Read
  0x01: Memory Read Lock (deprecated)
  0x02: I/O Read
  0x03: I/O Write
  0x04: Configuration Read
  0x05: Configuration Write
  0x0A: Completion with Data
  0x0B: Completion without Data
  0x10: Message
  0x11: Message with Data
```

## Usage Examples

### 1. Parse Memory Transaction

```python
from src.tlp_parser import TLPPacketAnalyzer, MemoryTransaction

analyzer = TLPPacketAnalyzer()

# Memory Write packet
mwr_packet = b'\x60\x00\x00\x01' \
             b'\x00\x00\x00\x08' \
             b'\x00\x00\xF0\x00' \
             b'\xDEADBEEF'

packet = analyzer.parse_tlp(mwr_packet)
print(f"Type: Memory Write")
print(f"Address: 0x{packet.address:08X}")
print(f"First BE: {packet.first_be:04b}")
print(f"Last BE: {packet.last_be:04b}")
```

### 2. Parse Completion Packet

```python
from src.tlp_parser import CompletionTransaction

cpl_packet = b'\x4A\x00\x00\x01' \
             b'\x00\x00\x00\x00' \
             b'\x00\x00\x00\x00' \
             b'\x00\x00\x00\x00'

packet = analyzer.parse_tlp(cpl_packet)
if isinstance(packet, CompletionTransaction):
    print(f"Status: {packet.status_name}")
    print(f"Byte Count: {packet.byte_count}")
    print(f"Lower Address: 0x{packet.lower_address:02X}")
```

### 3. Parse TLP Stream

```python
# Multiple TLP packets concatenated
tlp_stream = mwr_packet + cpl_packet

packets = analyzer.parse_tlp_stream(tlp_stream)
print(f"Parsed {len(packets)} packets")

analyzer.print_statistics()
```

## Testing

```bash
# Run unit tests
python -m pytest tests/

# Run with coverage
python -m pytest tests/ --cov=src
```

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## References

- PCIe 4.0 Base Specification
- PCI Express Technology Overview
- TLP Format and Structure Documentation
