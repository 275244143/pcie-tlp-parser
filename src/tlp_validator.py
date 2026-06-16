"""PCIe TLP Packet Validator

This module provides comprehensive validation and verification for PCIe TLP packets,
including format checking, field validation, and protocol compliance verification.
"""

import struct
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

from .tlp_types import TLPFormat, TLPType, CompletionStatus
from .utils import extract_field, bytes_to_dwords


class ValidationSeverity(Enum):
    """Severity levels for validation issues"""
    ERROR = "ERROR"          # Fatal issue, packet is invalid
    WARNING = "WARNING"      # Non-fatal issue, packet may work but is unusual
    INFO = "INFO"           # Informational, no issue


@dataclass
class ValidationIssue:
    """Represents a validation issue found in a TLP packet"""
    severity: ValidationSeverity
    code: str
    message: str
    field: Optional[str] = None
    value: Optional[Any] = None


class TLPValidator:
    """Validate PCIe TLP packets for correctness and compliance"""
    
    def __init__(self, strict_mode: bool = False):
        """
        Initialize TLP Validator
        
        Args:
            strict_mode: If True, warnings are treated as errors
        """
        self.strict_mode = strict_mode
        self.issues: List[ValidationIssue] = []
    
    def validate(self, packet: bytes) -> Tuple[bool, List[ValidationIssue]]:
        """
        Validate a TLP packet
        
        Args:
            packet: Raw packet bytes
            
        Returns:
            Tuple of (is_valid, list of validation issues)
        """
        self.issues = []
        
        # Basic structure validation
        if not self._validate_packet_structure(packet):
            return False, self.issues
        
        # Parse header
        dwords = bytes_to_dwords(packet)
        if len(dwords) == 0:
            self._add_issue(
                ValidationSeverity.ERROR,
                "EMPTY_PACKET",
                "Packet is empty"
            )
            return False, self.issues
        
        # Extract header fields
        fmt = extract_field(dwords[0], 30, 2)
        tlp_type = extract_field(dwords[0], 25, 5)
        tc = extract_field(dwords[0], 20, 3)
        td = extract_field(dwords[0], 18, 1)
        ep = extract_field(dwords[0], 17, 1)
        ln = extract_field(dwords[0], 16, 1)
        
        # Validate header format
        self._validate_format(fmt)
        self._validate_type(tlp_type)
        self._validate_traffic_class(tc)
        
        # Validate header completeness for this format
        expected_header_size = self._get_header_size(fmt)
        if len(dwords) < (expected_header_size // 4):
            self._add_issue(
                ValidationSeverity.ERROR,
                "INCOMPLETE_HEADER",
                f"Packet too short for format {fmt} (need {expected_header_size} bytes)"
            )
            return False, self.issues
        
        # Format-specific validation
        has_data = fmt in [2, 3]  # FMT_WITH_DATA
        
        if fmt in [0, 2]:  # 3DW format
            self._validate_3dw_header(dwords, packet, has_data)
        elif fmt in [1, 3]:  # 4DW format
            self._validate_4dw_header(dwords, packet, has_data)
        
        # Type-specific validation
        self._validate_type_specific(tlp_type, dwords, packet, fmt)
        
        # Check payload if data format
        if has_data:
            self._validate_payload(dwords, packet, fmt)
        
        # Determine final validity
        is_valid = not self._has_errors()
        
        if self.strict_mode and self._has_warnings():
            is_valid = False
        
        return is_valid, self.issues
    
    def get_validation_report(self, packet: bytes) -> str:
        """
        Get a formatted validation report
        
        Args:
            packet: Raw packet bytes
            
        Returns:
            Formatted validation report string
        """
        is_valid, issues = self.validate(packet)
        
        report = []
        report.append("=" * 60)
        report.append("TLP PACKET VALIDATION REPORT")
        report.append("=" * 60)
        report.append(f"Packet Size: {len(packet)} bytes")
        report.append(f"Valid: {'✓ YES' if is_valid else '✗ NO'}")
        report.append(f"Issues Found: {len(issues)}")
        report.append("")
        
        if not issues:
            report.append("No issues found!")
        else:
            # Group by severity
            errors = [i for i in issues if i.severity == ValidationSeverity.ERROR]
            warnings = [i for i in issues if i.severity == ValidationSeverity.WARNING]
            infos = [i for i in issues if i.severity == ValidationSeverity.INFO]
            
            if errors:
                report.append(f"ERRORS ({len(errors)}):")
                for issue in errors:
                    report.append(f"  ✗ [{issue.code}] {issue.message}")
                    if issue.field:
                        report.append(f"     Field: {issue.field} = {issue.value}")
                report.append("")
            
            if warnings:
                report.append(f"WARNINGS ({len(warnings)}):")
                for issue in warnings:
                    report.append(f"  ⚠ [{issue.code}] {issue.message}")
                    if issue.field:
                        report.append(f"     Field: {issue.field} = {issue.value}")
                report.append("")
            
            if infos:
                report.append(f"INFO ({len(infos)}):")
                for issue in infos:
                    report.append(f"  ℹ [{issue.code}] {issue.message}")
                report.append("")
        
        report.append("=" * 60)
        return "\n".join(report)
    
    # ===== Validation Methods =====
    
    def _validate_packet_structure(self, packet: bytes) -> bool:
        """Validate basic packet structure"""
        if len(packet) == 0:
            self._add_issue(
                ValidationSeverity.ERROR,
                "EMPTY_PACKET",
                "Packet is empty"
            )
            return False
        
        if len(packet) % 4 != 0:
            self._add_issue(
                ValidationSeverity.ERROR,
                "UNALIGNED_SIZE",
                f"Packet size {len(packet)} is not 4-byte aligned",
                "size"
            )
            return False
        
        if len(packet) < 12:
            self._add_issue(
                ValidationSeverity.ERROR,
                "TOO_SHORT",
                f"Packet size {len(packet)} < minimum 12 bytes",
                "size"
            )
            return False
        
        return True
    
    def _validate_format(self, fmt: int):
        """Validate Format field"""
        if not 0 <= fmt <= 3:
            self._add_issue(
                ValidationSeverity.ERROR,
                "INVALID_FORMAT",
                f"Invalid format value: {fmt}",
                "format",
                fmt
            )
    
    def _validate_type(self, tlp_type: int):
        """Validate Type field"""
        valid_types = {
            0x00, 0x01,  # MRd, MRdLk
            0x02, 0x03,  # IORd, IOWr
            0x04, 0x05,  # CFRd, CFWr
            0x0A, 0x0B, 0x0C, 0x0D,  # Cpl, CplD, LCpl, LCplD
            0x10, 0x11   # Msg, MsgD
        }
        
        if tlp_type not in valid_types:
            self._add_issue(
                ValidationSeverity.WARNING,
                "UNKNOWN_TYPE",
                f"Unknown or reserved type: 0x{tlp_type:02X}",
                "type",
                f"0x{tlp_type:02X}"
            )
    
    def _validate_traffic_class(self, tc: int):
        """Validate Traffic Class field"""
        if not 0 <= tc <= 7:
            self._add_issue(
                ValidationSeverity.ERROR,
                "INVALID_TC",
                f"Invalid traffic class: {tc}",
                "traffic_class",
                tc
            )
    
    def _validate_3dw_header(self, dwords: List[int], packet: bytes, has_data: bool):
        """Validate 3 DWORD header format"""
        if len(dwords) < 3:
            self._add_issue(
                ValidationSeverity.ERROR,
                "SHORT_3DW_HEADER",
                "3DW format requires at least 3 DWORDs"
            )
            return
        
        # DW0: Common
        # DW1: Tag [31:24], Requester ID [23:8], BE [7:0]
        dw1 = dwords[1]
        requester_id = extract_field(dw1, 16, 16)
        
        if not 0 <= requester_id <= 0xFFFF:
            self._add_issue(
                ValidationSeverity.WARNING,
                "INVALID_RID",
                f"Invalid Requester ID: 0x{requester_id:04X}",
                "requester_id",
                f"0x{requester_id:04X}"
            )
        
        # DW2: Length [9:0]
        dw2 = dwords[2]
        length = extract_field(dw2, 0, 10)
        
        if length == 0:
            self._add_issue(
                ValidationSeverity.INFO,
                "ZERO_LENGTH",
                "Length field is 0 (represents 4096 DWORDs)",
                "length",
                0
            )
    
    def _validate_4dw_header(self, dwords: List[int], packet: bytes, has_data: bool):
        """Validate 4 DWORD header format"""
        if len(dwords) < 4:
            self._add_issue(
                ValidationSeverity.ERROR,
                "SHORT_4DW_HEADER",
                "4DW format requires at least 4 DWORDs"
            )
            return
        
        # DW1: Similar to 3DW
        dw1 = dwords[1]
        requester_id = extract_field(dw1, 16, 16)
        
        if not 0 <= requester_id <= 0xFFFF:
            self._add_issue(
                ValidationSeverity.WARNING,
                "INVALID_RID",
                f"Invalid Requester ID: 0x{requester_id:04X}",
                "requester_id",
                f"0x{requester_id:04X}"
            )
    
    def _validate_type_specific(
        self,
        tlp_type: int,
        dwords: List[int],
        packet: bytes,
        fmt: int
    ):
        """Validate type-specific requirements"""
        has_data = fmt in [2, 3]
        
        # Memory Read should not have data format
        if tlp_type == 0x00 and has_data:
            self._add_issue(
                ValidationSeverity.ERROR,
                "MRD_WITH_DATA",
                "Memory Read (MRd) should use format without data",
                "type/format"
            )
        
        # I/O transactions should be 3DW
        if tlp_type in [0x02, 0x03] and fmt not in [0, 2]:
            self._add_issue(
                ValidationSeverity.WARNING,
                "IO_4DW_FORMAT",
                "I/O transactions typically use 3DW format, not 4DW",
                "format",
                fmt
            )
        
        # Config transactions should be 3DW
        if tlp_type in [0x04, 0x05] and fmt not in [0, 2]:
            self._add_issue(
                ValidationSeverity.WARNING,
                "CFG_4DW_FORMAT",
                "Config transactions typically use 3DW format, not 4DW",
                "format",
                fmt
            )
        
        # Completion validation
        if tlp_type in [0x0A, 0x0B, 0x0C, 0x0D]:
            self._validate_completion(dwords, tlp_type, has_data)
    
    def _validate_completion(self, dwords: List[int], tlp_type: int, has_data: bool):
        """Validate completion packet"""
        if len(dwords) < 4:
            self._add_issue(
                ValidationSeverity.ERROR,
                "SHORT_CPL_HEADER",
                "Completion requires at least 4 DWORDs"
            )
            return
        
        # CplD requires data format
        if tlp_type == 0x0A and not has_data:
            self._add_issue(
                ValidationSeverity.ERROR,
                "CPLD_NO_DATA",
                "Completion with Data (CplD) should have data",
                "type/format"
            )
        
        # Cpl should not have data format
        if tlp_type == 0x0B and has_data:
            self._add_issue(
                ValidationSeverity.WARNING,
                "CPL_WITH_DATA",
                "Completion without Data (Cpl) should not have data format",
                "type/format"
            )
        
        # Validate completion status
        dw1 = dwords[1]
        status = extract_field(dw1, 13, 3)
        
        valid_statuses = [0, 1, 2, 4]
        if status not in valid_statuses:
            self._add_issue(
                ValidationSeverity.ERROR,
                "INVALID_CPL_STATUS",
                f"Invalid completion status: {status}",
                "cpl_status",
                status
            )
    
    def _validate_payload(self, dwords: List[int], packet: bytes, fmt: int):
        """Validate payload"""
        header_size = self._get_header_size(fmt)
        payload_size = len(packet) - header_size
        
        if payload_size < 0:
            self._add_issue(
                ValidationSeverity.ERROR,
                "PAYLOAD_OVERFLOW",
                "Packet too small for declared header format"
            )
            return
        
        if payload_size % 4 != 0:
            self._add_issue(
                ValidationSeverity.ERROR,
                "UNALIGNED_PAYLOAD",
                f"Payload size {payload_size} is not 4-byte aligned"
            )
            return
        
        # Extract length field
        dw2 = dwords[2]
        length = extract_field(dw2, 0, 10)
        
        # For 4DW, length is in DW3
        if fmt in [1, 3]:
            dw3 = dwords[3]
            length = extract_field(dw3, 0, 10)
        
        expected_payload = length * 4
        
        if length == 0:
            # Length 0 means 4096 DWORDs
            expected_payload = 4096 * 4
        
        if payload_size > 0 and length > 0 and payload_size != expected_payload:
            self._add_issue(
                ValidationSeverity.WARNING,
                "LENGTH_MISMATCH",
                f"Length field ({length} DW = {expected_payload} B) != actual payload ({payload_size} B)"
            )
    
    # ===== Helper Methods =====
    
    @staticmethod
    def _get_header_size(fmt: int) -> int:
        """Get header size in bytes for format"""
        if fmt in [0, 2]:  # 3DW format
            return 12
        else:  # 4DW format
            return 16
    
    def _add_issue(
        self,
        severity: ValidationSeverity,
        code: str,
        message: str,
        field: Optional[str] = None,
        value: Optional[Any] = None
    ):
        """Add a validation issue"""
        issue = ValidationIssue(severity, code, message, field, value)
        self.issues.append(issue)
    
    def _has_errors(self) -> bool:
        """Check if any errors exist"""
        return any(i.severity == ValidationSeverity.ERROR for i in self.issues)
    
    def _has_warnings(self) -> bool:
        """Check if any warnings exist"""
        return any(i.severity == ValidationSeverity.WARNING for i in self.issues)


def validate_tlp_packet(packet: bytes, strict: bool = False) -> Dict[str, Any]:
    """
    Convenience function to validate a TLP packet
    
    Args:
        packet: Raw packet bytes
        strict: If True, warnings are treated as errors
        
    Returns:
        Dictionary with validation results
    """
    validator = TLPValidator(strict_mode=strict)
    is_valid, issues = validator.validate(packet)
    
    return {
        "valid": is_valid,
        "packet_size": len(packet),
        "issue_count": len(issues),
        "errors": len([i for i in issues if i.severity == ValidationSeverity.ERROR]),
        "warnings": len([i for i in issues if i.severity == ValidationSeverity.WARNING]),
        "issues": issues,
        "report": validator.get_validation_report(packet)
    }
