"""UEFI firmware analyzer for Blackfyre"""

import os
import re
import io
import uuid
import json
import struct
import logging
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any, Union, Iterator
from blackfyre.datatypes.contexts.binarycontext import BinaryContext
from blackfyre.analyzers.firmware import FirmwareAnalyzer

# UEFI GUID format: 32 bits + 16 bits + 16 bits + 64 bits
GUID_FMT = '<IHH8B'

# Known UEFI firmware volume GUIDs
KNOWN_FV_GUIDS = {
    "8c8ce578-8a3d-4f1c-9935-896185c32dd3": "EFI_FIRMWARE_FILE_SYSTEM2_GUID",
    "5473c07a-3dcb-4dca-bd6f-1e9689e7349a": "EFI_FIRMWARE_FILE_SYSTEM3_GUID",
    "fff12b8d-7696-4c8b-a985-2747075b4f50": "EFI_SYSTEM_NV_DATA_FV_GUID",
    "7a9354d9-0468-444a-81ce-0bf617d890df": "EFI_FFS_VOLUME_TOP_FILE_GUID"
}

# Known UEFI file types
EFI_FV_FILETYPE_RAW = 0x01
EFI_FV_FILETYPE_FREEFORM = 0x02
EFI_FV_FILETYPE_SECURITY_CORE = 0x03
EFI_FV_FILETYPE_PEI_CORE = 0x04
EFI_FV_FILETYPE_DXE_CORE = 0x05
EFI_FV_FILETYPE_PEIM = 0x06
EFI_FV_FILETYPE_DRIVER = 0x07
EFI_FV_FILETYPE_COMBINED_PEIM_DRIVER = 0x08
EFI_FV_FILETYPE_APPLICATION = 0x09
EFI_FV_FILETYPE_MM = 0x0A
EFI_FV_FILETYPE_FIRMWARE_VOLUME_IMAGE = 0x0B
EFI_FV_FILETYPE_COMBINED_MM_DXE = 0x0C
EFI_FV_FILETYPE_MM_CORE = 0x0D
EFI_FV_FILETYPE_MM_STANDALONE = 0x0E
EFI_FV_FILETYPE_MM_CORE_STANDALONE = 0x0F
EFI_FV_FILETYPE_PAD = 0xF0

class UEFIFirmwareAnalyzer:
    """Analyzer for UEFI firmware images"""
    
    def __init__(self, 
                 binary_context: Optional[BinaryContext] = None,
                 firmware_path: Optional[str] = None,
                 extraction_dir: Optional[str] = None):
        """Initialize the UEFI firmware analyzer
        
        Args:
            binary_context: BinaryContext with firmware data (if already loaded)
            firmware_path: Path to firmware file (if not loaded via BinaryContext)
            extraction_dir: Directory to extract firmware components
        """
        # Use the firmware analyzer as base
        self.firmware_analyzer = FirmwareAnalyzer(
            binary_context=binary_context,
            firmware_path=firmware_path,
            extraction_dir=extraction_dir
        )
        
        self.logger = logging.getLogger(__name__)
        self.firmware_volumes = []
        self.firmware_files = []
        self.sections = []
        self.uefi_drivers = []
    
    def load_firmware(self) -> bool:
        """Load firmware data from file
        
        Returns:
            True if successfully loaded
        """
        return self.firmware_analyzer.load_firmware()
    
    def scan_firmware_volumes(self) -> List[Dict[str, Any]]:
        """Scan for UEFI firmware volumes
        
        Returns:
            List of firmware volume information
        """
        if not self.firmware_analyzer.firmware_data:
            if not self.load_firmware():
                return []
                
        self.firmware_volumes = []
        data = self.firmware_analyzer.firmware_data
        
        # UEFI firmware volume signature "_FVH"
        self.logger.info("Scanning for UEFI firmware volumes...")
        fv_signature = b'_FVH'
        fv_matches = []
        
        offset = 0
        while True:
            offset = data.find(fv_signature, offset)
            if offset == -1:
                break
            
            # Firmware volume header should be 40 bytes before signature
            potential_fv_offset = offset - 40
            if potential_fv_offset >= 0:
                fv_matches.append(potential_fv_offset)
            
            offset += 4
        
        for offset in fv_matches:
            try:
                fv_info = self._parse_firmware_volume(data, offset)
                if fv_info:
                    self.firmware_volumes.append(fv_info)
                    self.logger.info(f"Found UEFI firmware volume at offset 0x{offset:x}, size {fv_info['size']} bytes")
            except Exception as e:
                self.logger.error(f"Error parsing firmware volume at 0x{offset:x}: {e}")
        
        # Extract the firmware volumes
        for fv in self.firmware_volumes:
            try:
                fv_data = data[fv['offset']:fv['offset'] + fv['size']]
                output_path = os.path.join(self.firmware_analyzer.extraction_dir, f"fv_{fv['offset']:x}.bin")
                
                with open(output_path, 'wb') as f:
                    f.write(fv_data)
                    
                fv['path'] = output_path
                self.logger.info(f"Extracted firmware volume to {output_path}")
            except Exception as e:
                self.logger.error(f"Error extracting firmware volume at 0x{fv['offset']:x}: {e}")
        
        # Create summary file
        summary_path = os.path.join(self.firmware_analyzer.extraction_dir, "uefi_summary.json")
        with open(summary_path, 'w') as f:
            json.dump({
                "firmware_volumes": self.firmware_volumes
            }, f, indent=2)
            
        return self.firmware_volumes
    
    def _parse_firmware_volume(self, data: bytes, offset: int) -> Optional[Dict[str, Any]]:
        """Parse UEFI firmware volume
        
        Args:
            data: Firmware data
            offset: Offset of firmware volume
            
        Returns:
            Firmware volume information
        """
        if offset + 56 > len(data):  # Minimum size of FV header
            return None
            
        # Parse firmware volume header
        zero_vector = data[offset:offset+16]
        if zero_vector != b'\x00' * 16:
            return None  # ZeroVector should be all zeros
            
        # Parse GUID bytes
        guid_bytes = data[offset+16:offset+32]
        guid = self._parse_guid(guid_bytes)
        
        # Parse FV size
        fv_size = struct.unpack('<Q', data[offset+32:offset+40])[0]
        
        # Validate FV size
        if offset + fv_size > len(data):
            return None
            
        # Parse attributes and header size
        attributes = struct.unpack('<I', data[offset+40:offset+44])[0]
        header_size = struct.unpack('<H', data[offset+44:offset+46])[0]
        
        # Parse signature (_FVH)
        signature = data[offset+40+16:offset+40+20]
        
        if signature != b'_FVH':
            return None
            
        return {
            'offset': offset,
            'size': fv_size,
            'guid': guid,
            'guid_name': KNOWN_FV_GUIDS.get(guid, "Unknown"),
            'attributes': attributes,
            'header_size': header_size
        }
    
    def _parse_guid(self, guid_bytes: bytes) -> str:
        """Parse GUID from bytes
        
        Args:
            guid_bytes: 16 bytes representing a GUID
            
        Returns:
            GUID string in the format 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
        """
        if len(guid_bytes) != 16:
            raise ValueError("GUID must be 16 bytes")
            
        # Unpack GUID bytes
        values = struct.unpack(GUID_FMT, guid_bytes)
        
        # Format GUID string
        data1 = values[0]
        data2 = values[1]
        data3 = values[2]
        data4 = ''.join(f"{b:02x}" for b in values[3:])
        
        return f"{data1:08x}-{data2:04x}-{data3:04x}-{data4[:4]}-{data4[4:]}"
    
    def scan_for_pe_files(self) -> List[Dict[str, Any]]:
        """Scan firmware volumes for PE files
        
        Returns:
            List of PE file information
        """
        if not self.firmware_volumes:
            self.scan_firmware_volumes()
            
        self.uefi_drivers = []
        
        for fv in self.firmware_volumes:
            try:
                if 'path' not in fv:
                    continue
                    
                with open(fv['path'], 'rb') as f:
                    fv_data = f.read()
                    
                # Look for PE headers ('MZ')
                offset = 0
                while True:
                    offset = fv_data.find(b'MZ', offset)
                    if offset == -1:
                        break
                        
                    # Validate PE header
                    if offset + 0x40 < len(fv_data):
                        pe_offset = struct.unpack('<I', fv_data[offset+0x3C:offset+0x40])[0]
                        if offset + pe_offset + 4 < len(fv_data) and fv_data[offset+pe_offset:offset+pe_offset+4] == b'PE\x00\x00':
                            self.logger.info(f"Found PE file in firmware volume at offset 0x{offset:x}")
                            
                            # Extract PE file
                            pe_size = self._determine_pe_size(fv_data, offset)
                            if pe_size:
                                output_path = os.path.join(self.firmware_analyzer.extraction_dir, f"pe_driver_{fv['offset']:x}_{offset:x}.efi")
                                
                                with open(output_path, 'wb') as pe_f:
                                    pe_f.write(fv_data[offset:offset+pe_size])
                                    
                                self.uefi_drivers.append({
                                    'type': 'PE',
                                    'fv_offset': fv['offset'],
                                    'offset': offset,
                                    'size': pe_size,
                                    'path': output_path
                                })
                                
                                self.logger.info(f"Extracted PE file to {output_path}")
                            
                    offset += 2
            except Exception as e:
                self.logger.error(f"Error scanning firmware volume at 0x{fv['offset']:x} for PE files: {e}")
        
        # Create summary file
        summary_path = os.path.join(self.firmware_analyzer.extraction_dir, "uefi_drivers.json")
        with open(summary_path, 'w') as f:
            json.dump({
                "uefi_drivers": self.uefi_drivers
            }, f, indent=2)
            
        return self.uefi_drivers
    
    def _determine_pe_size(self, data: bytes, offset: int) -> int:
        """Determine size of PE file
        
        Args:
            data: Firmware data
            offset: Offset of PE file
            
        Returns:
            Size of PE file in bytes
        """
        # This is a simplified approach
        # In a real implementation, we would parse the PE header
        
        # Look for the next PE header or end of data
        next_pe = data.find(b'MZ', offset + 2)
        if next_pe == -1:
            # No next PE, use remaining data
            return len(data) - offset
        else:
            # Found next PE, use difference
            return next_pe - offset
    
    def generate_report(self, output_file: Optional[str] = None) -> str:
        """Generate UEFI analysis report
        
        Args:
            output_file: Path to save the report to
            
        Returns:
            Path to the generated report
        """
        # Run analysis if not already done
        if not self.firmware_volumes:
            self.scan_firmware_volumes()
            
        if not self.uefi_drivers:
            self.scan_for_pe_files()
            
        # Create report directory
        report_dir = os.path.join(self.firmware_analyzer.extraction_dir, "report")
        os.makedirs(report_dir, exist_ok=True)
        
        # Set default output file if not provided
        if not output_file:
            output_file = os.path.join(report_dir, "uefi_analysis_report.md")
        
        # Generate report content
        report = f"""# UEFI Firmware Analysis Report

## Overview

- **File Size:** {len(self.firmware_analyzer.firmware_data)} bytes
- **Extracted To:** {self.firmware_analyzer.extraction_dir}
- **Firmware Volumes:** {len(self.firmware_volumes)}
- **UEFI Drivers/Applications:** {len(self.uefi_drivers)}

## Firmware Volumes

"""

        for i, fv in enumerate(self.firmware_volumes, 1):
            report += f"### {i}. Firmware Volume\n\n"
            report += f"- **Offset:** 0x{fv['offset']:x}\n"
            report += f"- **Size:** {fv['size']} bytes\n"
            report += f"- **GUID:** {fv['guid']} ({fv['guid_name']})\n"
            if 'path' in fv:
                report += f"- **Path:** {fv['path']}\n"
            report += "\n"
            
        report += "\n## UEFI Drivers/Applications\n\n"
        
        for i, driver in enumerate(self.uefi_drivers, 1):
            report += f"### {i}. UEFI Driver\n\n"
            report += f"- **Offset:** 0x{driver['offset']:x} (in FV at 0x{driver['fv_offset']:x})\n"
            report += f"- **Size:** {driver['size']} bytes\n"
            report += f"- **Path:** {driver['path']}\n\n"
            
        # Write report to file
        with open(output_file, 'w') as f:
            f.write(report)
            
        return output_file
