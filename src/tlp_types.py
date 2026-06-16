"""PCIe TLP Type Definitions"""

from enum import Enum
from dataclasses import dataclass
from typing import Dict, Optional


class TLPType(Enum):
    """PCIe Transaction Layer Packet Types"""
    
    # Memory Transactions
    MRd = 0x00      # Memory Read
    MRdLk = 0x01    # Memory Read Lock (deprecated in PCIe 3.0+)
    MWr = 0x00      # Memory Write (same as MRd, differentiated by format)
    IORd = 0x02     # I/O Read
    IOWr = 0x03     # I/O Write
    CFRd = 0x04     # Configuration Read Type 0
    CFWr = 0x05     # Configuration Write Type 0
    
    # Completion Transactions
    TCplD = 0x0A    # Completion with Data
    Cpl = 0x0B      # Completion without Data
    LCplD = 0x0C    # Locked Completion with Data (deprecated)
    LCpl = 0x0D     # Locked Completion without Data (deprecated)
    
    # Message Transactions
    Msg = 0x10      # Message (no data)
    MsgD = 0x11     # Message with Data


class TLPFormat(Enum):
    """TLP Header Format"""
    FMT_3DW_NO_DATA = 0     # 3 DW header, no data
    FMT_4DW_NO_DATA = 1     # 4 DW header, no data (legacy)
    FMT_3DW_WITH_DATA = 2   # 3 DW header, with data
    FMT_4DW_WITH_DATA = 3   # 4 DW header, with data


class CompletionStatus(Enum):
    """Completion Status"""
    SC = 0          # Successful Completion
    UR = 1          # Unsupported Request
    CRS = 2         # Configuration Request Retry Status
    CA = 4          # Completer Abort


class MessageCode(Enum):
    """PCIe Message Codes"""
    UNLOCK = 0x00
    ASSERT_INTA = 0x01
    ASSERT_INTB = 0x02
    ASSERT_INTC = 0x03
    ASSERT_INTD = 0x04
    DEASSERT_INTA = 0x05
    DEASSERT_INTB = 0x06
    DEASSERT_INTC = 0x07
    DEASSERT_INTD = 0x08
    
    PM_ACTIVE_STATE_NAK = 0x10
    PM_PME = 0x14
    
    ERR_CORRECTABLE = 0x20
    ERR_NONFATAL = 0x21
    ERR_FATAL = 0x22
    
    WAKE = 0x30


@dataclass
class TLPFieldDefinition:
    """Definition of a TLP field for documentation"""
    name: str
    offset: int  # Offset in bits from start of header
    width: int   # Field width in bits
    description: str
    format: str  # Format hint: 'hex', 'decimal', 'binary', 'enum'


# PCIe TLP Field Definitions
TLP_FIELD_DEFINITIONS: Dict[str, TLPFieldDefinition] = {
    # First DWORD (Common to all)
    'fmt': TLPFieldDefinition(
        'Format', 30, 2, 'Header format (3DW/4DW, with/without data)', 'hex'
    ),
    'type': TLPFieldDefinition(
        'Type', 24, 5, 'Transaction type', 'hex'
    ),
    'tc': TLPFieldDefinition(
        'Traffic Class', 20, 3, 'Traffic class', 'hex'
    ),
    'ln': TLPFieldDefinition(
        'TLP Processing Hints', 18, 1, 'TLP Processing Hints', 'binary'
    ),
    'th': TLPFieldDefinition(
        'TLP Hints', 17, 1, 'TLP Digest present', 'binary'
    ),
    'td': TLPFieldDefinition(
        'Digest', 16, 1, 'Data is poisoned', 'binary'
    ),
    'ep': TLPFieldDefinition(
        'Error Poison', 14, 1, 'Error poisoned', 'binary'
    ),
    
    # Routing bits
    'rid': TLPFieldDefinition(
        'Requester ID', 0, 16, 'Requester Bus/Device/Function', 'hex'
    ),
    
    # Second DWORD
    'tag': TLPFieldDefinition(
        'Tag', 24, 8, 'Transaction tag', 'hex'
    ),
    'length': TLPFieldDefinition(
        'Length', 0, 10, 'Length in DWORDs (0=4KB)', 'decimal'
    ),
}


def get_message_type_name(msg_code: int) -> str:
    """Get human-readable message type name"""
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
    return msg_names.get(msg_code, f"Unknown(0x{msg_code:02X})")


def get_completion_status_name(status: int) -> str:
    """Get human-readable completion status name"""
    status_names = {
        0: "Successful Completion",
        1: "Unsupported Request",
        2: "Configuration Request Retry Status",
        4: "Completer Abort",
    }
    return status_names.get(status, f"Reserved({status})")
