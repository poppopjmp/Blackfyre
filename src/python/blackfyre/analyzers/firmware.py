"""Firmware analysis module for Blackfyre"""

import os
import re
import json
import struct
import binascii
import logging
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any, Union, Iterator
from blackfyre.datatypes.contexts.binarycontext import BinaryContext

class FirmwareAnalyzer:
    """Analyzer for firmware files and images"""
    
    def __init__(self, 
                 binary_context: Optional[BinaryContext] = None,
                 firmware_path: Optional[str] = None,
                 extraction_dir: Optional[str] = None):
        """Initialize the firmware analyzer
        
        Args:
            binary_context: BinaryContext with firmware data (if already loaded)
            firmware_path: Path to firmware file (if not loaded via BinaryContext)
            extraction_dir: Directory to extract firmware components
        """
        self.binary_context = binary_context
        self.firmware_path = firmware_path
        
        # Set up extraction directory
        if extraction_dir:
            self.extraction_dir = Path(extraction_dir)
        elif firmware_path:
            # Default extraction directory next to firmware file
            parent = Path(firmware_path).parent
            base_name = Path(firmware_path).stem
            self.extraction_dir = parent / f"{base_name}_extracted"
        else:
            self.extraction_dir = Path("firmware_extracted")
        
        self.logger = logging.getLogger(__name__)
        self.firmware_data = None
        self.embedded_binaries = []
        self.file_system_areas = []
        self.headers = {}
        self.components = {}
    
    def load_firmware(self) -> bool:
        """Load firmware data from file
        
        Returns:
            True if successfully loaded
        """
        if self.binary_context:
            # Use the binary data from the context
            if hasattr(self.binary_context, 'raw_data') and self.binary_context.raw_data:
                self.firmware_data = self.binary_context.raw_data
                self.logger.info(f"Loaded {len(self.firmware_data)} bytes from BinaryContext")
                return True
        
        # Load from file if provided
        if self.firmware_path and os.path.exists(self.firmware_path):
            try:
                with open(self.firmware_path, 'rb') as f:
                    self.firmware_data = f.read()
                self.logger.info(f"Loaded {len(self.firmware_data)} bytes from {self.firmware_path}")
                return True
            except Exception as e:
                self.logger.error(f"Error loading firmware file: {e}")
                return False
        
        self.logger.error("No firmware data or valid path provided")
        return False
    
    def scan_for_embedded_binaries(self) -> List[Dict[str, Any]]:
        """Scan firmware for embedded binary files
        
        Returns:
            List of dictionaries with information about found binaries
        """
        if not self.firmware_data:
            if not self.load_firmware():
                return []
        
        # Create extraction directory if needed
        os.makedirs(self.extraction_dir, exist_ok=True)
        
        # Reset results
        self.embedded_binaries = []
        
        # Look for ELF headers (0x7F 'E' 'L' 'F')
        self.logger.info("Scanning for ELF binaries...")
        elf_matches = self._find_pattern(b'\x7FELF')
        for offset in elf_matches:
            self.logger.info(f"Found potential ELF header at offset 0x{offset:x}")
            size = self._determine_binary_size(offset, 'ELF')
            if size:
                binary_info = {
                    'type': 'ELF',
                    'offset': offset,
                    'size': size,
                    'path': self._extract_binary(offset, size, f"elf_binary_{offset:x}")
                }
                self.embedded_binaries.append(binary_info)
                self.logger.info(f"Extracted ELF binary: {binary_info['path']}, size: {size} bytes")
        
        # Look for PE headers ('MZ')
        self.logger.info("Scanning for PE binaries...")
        pe_matches = self._find_pattern(b'MZ')
        for offset in pe_matches:
            # Validate PE header
            if offset + 0x40 < len(self.firmware_data):
                pe_offset = struct.unpack('<I', self.firmware_data[offset+0x3C:offset+0x40])[0]
                if offset + pe_offset + 4 < len(self.firmware_data) and self.firmware_data[offset+pe_offset:offset+pe_offset+4] == b'PE\x00\x00':
                    self.logger.info(f"Found valid PE header at offset 0x{offset:x}")
                    size = self._determine_binary_size(offset, 'PE')
                    if size:
                        binary_info = {
                            'type': 'PE',
                            'offset': offset,
                            'size': size,
                            'path': self._extract_binary(offset, size, f"pe_binary_{offset:x}")
                        }
                        self.embedded_binaries.append(binary_info)
                        self.logger.info(f"Extracted PE binary: {binary_info['path']}, size: {size} bytes")
        
        # Look for Mach-O binaries
        self.logger.info("Scanning for Mach-O binaries...")
        macho_magic_32 = struct.pack('<I', 0xfeedface)  # 32-bit
        macho_magic_64 = struct.pack('<I', 0xfeedfacf)  # 64-bit
        
        macho_matches = self._find_pattern(macho_magic_32) + self._find_pattern(macho_magic_64)
        for offset in macho_matches:
            self.logger.info(f"Found potential Mach-O header at offset 0x{offset:x}")
            size = self._determine_binary_size(offset, 'MachO')
            if size:
                binary_info = {
                    'type': 'MachO',
                    'offset': offset,
                    'size': size,
                    'path': self._extract_binary(offset, size, f"macho_binary_{offset:x}")
                }
                self.embedded_binaries.append(binary_info)
                self.logger.info(f"Extracted Mach-O binary: {binary_info['path']}, size: {size} bytes")
                
        # Create summary file
        summary_path = os.path.join(self.extraction_dir, "binary_summary.json")
        with open(summary_path, 'w') as f:
            json.dump({
                "firmware_size": len(self.firmware_data),
                "embedded_binaries": self.embedded_binaries
            }, f, indent=2)
            
        return self.embedded_binaries
    
    def _find_pattern(self, pattern: bytes) -> List[int]:
        """Find all occurrences of a pattern in firmware
        
        Args:
            pattern: Byte pattern to search for
            
        Returns:
            List of offsets where pattern was found
        """
        offsets = []
        offset = 0
        
        while True:
            offset = self.firmware_data.find(pattern, offset)
            if offset == -1:
                break
            offsets.append(offset)
            offset += 1
            
        return offsets
    
    def _determine_binary_size(self, offset: int, binary_type: str) -> Optional[int]:
        """Try to determine the size of a binary at the given offset
        
        Args:
            offset: Offset of binary in firmware
            binary_type: Type of binary ('ELF', 'PE', 'MachO')
            
        Returns:
            Size of binary in bytes, or None if can't be determined
        """
        # This is a simplified approach - in real implementation,
        # we would parse the actual headers to get proper size
        
        # For demonstration, search for next binary marker or use a reasonable maximum
        next_marker_offsets = []
        
        # Look for next ELF, PE, or Mach-O header
        for pattern in [b'\x7FELF', b'MZ', struct.pack('<I', 0xfeedface), struct.pack('<I', 0xfeedfacf)]:
            next_offset = self.firmware_data.find(pattern, offset + len(pattern))
            if next_offset > offset:
                next_marker_offsets.append(next_offset)
        
        # If we found any markers, use the closest one
        if next_marker_offsets:
            size = min(next_marker_offsets) - offset
        else:
            # Use a maximum size if we can't find the next header
            if binary_type == 'ELF':
                size = min(20 * 1024 * 1024, len(self.firmware_data) - offset)  # 20MB max
            elif binary_type == 'PE':
                size = min(20 * 1024 * 1024, len(self.firmware_data) - offset)  # 20MB max
            else:
                size = min(20 * 1024 * 1024, len(self.firmware_data) - offset)  # 20MB max
        
        return size
    
    def _extract_binary(self, offset: int, size: int, name: str) -> str:
        """Extract a binary from firmware data
        
        Args:
            offset: Offset of binary in firmware
            size: Size of binary in bytes
            name: Base name for the output file
            
        Returns:
            Path to extracted binary
        """
        binary_data = self.firmware_data[offset:offset+size]
        output_path = os.path.join(self.extraction_dir, f"{name}")
        
        with open(output_path, 'wb') as f:
            f.write(binary_data)
            
        return output_path
    
    def scan_for_file_systems(self) -> List[Dict[str, Any]]:
        """Scan firmware for embedded file systems
        
        Returns:
            List of dictionaries with information about found file systems
        """
        if not self.firmware_data:
            if not self.load_firmware():
                return []
        
        # Create extraction directory if needed
        os.makedirs(self.extraction_dir, exist_ok=True)
        
        # Reset results
        self.file_system_areas = []
        
        # Scan for common file system headers
        
        # SquashFS magic: 'hsqs' (little-endian) or 'sqsh' (big-endian)
        self.logger.info("Scanning for SquashFS...")
        squashfs_matches = self._find_pattern(b'hsqs') + self._find_pattern(b'sqsh')
        for offset in squashfs_matches:
            self.logger.info(f"Found potential SquashFS at offset 0x{offset:x}")
            fs_info = {
                'type': 'SquashFS',
                'offset': offset,
                'path': self._extract_file_system(offset, 'squashfs')
            }
            self.file_system_areas.append(fs_info)
        
        # JFFS2 magic: 0x1985
        self.logger.info("Scanning for JFFS2...")
        jffs2_magic = struct.pack('<H', 0x1985)
        jffs2_matches = self._find_pattern(jffs2_magic)
        for offset in jffs2_matches:
            # Validate JFFS2 node header
            if offset + 8 < len(self.firmware_data):
                node_type = self.firmware_data[offset+4]
                if node_type in (0x01, 0x02):  # JFFS2_NODETYPE_DIRENT or JFFS2_NODETYPE_INODE
                    self.logger.info(f"Found potential JFFS2 at offset 0x{offset:x}")
                    fs_info = {
                        'type': 'JFFS2',
                        'offset': offset,
                        'path': self._extract_file_system(offset, 'jffs2')
                    }
                    self.file_system_areas.append(fs_info)

        # Ext2/3/4 filesystem (look for superblock magic at offset 0x438)
        self.logger.info("Scanning for ext2/3/4 filesystems...")
        ext_magic = b'\x53\xEF'  # 0xEF53 in little-endian
        for offset in range(0, len(self.firmware_data) - 1024, 1024):  # Check at 1K intervals
            if offset + 0x438 + 2 <= len(self.firmware_data):
                if self.firmware_data[offset+0x438:offset+0x438+2] == ext_magic:
                    self.logger.info(f"Found potential ext2/3/4 filesystem at offset 0x{offset:x}")
                    fs_info = {
                        'type': 'ext',
                        'offset': offset,
                        'path': self._extract_file_system(offset, 'ext')
                    }
                    self.file_system_areas.append(fs_info)

        # UBI/UBIFS (UBI magic is "UBI#")
        self.logger.info("Scanning for UBI/UBIFS volumes...")
        ubi_matches = self._find_pattern(b'UBI#')
        for offset in ubi_matches:
            self.logger.info(f"Found potential UBI volume at offset 0x{offset:x}")
            fs_info = {
                'type': 'UBI',
                'offset': offset,
                'path': self._extract_file_system(offset, 'ubi')
            }
            self.file_system_areas.append(fs_info)
        
        # Create summary file
        summary_path = os.path.join(self.extraction_dir, "filesystem_summary.json")
        with open(summary_path, 'w') as f:
            json.dump({
                "firmware_size": len(self.firmware_data),
                "file_systems": self.file_system_areas
            }, f, indent=2)
            
        return self.file_system_areas

    def scan_for_containers(self) -> List[Dict[str, Any]]:
        """Scan firmware for container/archive formats
        
        Returns:
            List of dictionaries with container information
        """
        if not self.firmware_data:
            if not self.load_firmware():
                return []
        
        # Create extraction directory if needed
        os.makedirs(self.extraction_dir, exist_ok=True)
        
        # Results list
        containers = []
        
        # Scan for CPIO archives (used in initramfs)
        self.logger.info("Scanning for CPIO archives...")
        # CPIO new ASCII format magic: "070701"
        cpio_matches = self._find_pattern(b'070701') + self._find_pattern(b'070702')
        for offset in cpio_matches:
            self.logger.info(f"Found potential CPIO archive at offset 0x{offset:x}")
            container_info = {
                'type': 'CPIO',
                'offset': offset,
                'path': self._extract_container(offset, 'cpio')
            }
            containers.append(container_info)
        
        # Scan for TAR archives
        self.logger.info("Scanning for TAR archives...")
        # Look for POSIX tar format
        for offset in range(0, len(self.firmware_data) - 512, 512):  # TAR blocks are 512 bytes
            if offset + 257 < len(self.firmware_data):
                # Check for ustar magic at offset 257
                if self.firmware_data[offset+257:offset+262] == b'ustar':
                    self.logger.info(f"Found potential TAR archive at offset 0x{offset:x}")
                    container_info = {
                        'type': 'TAR',
                        'offset': offset,
                        'path': self._extract_container(offset, 'tar')
                    }
                    containers.append(container_info)
                    # Skip ahead to avoid finding the same archive multiple times
                    offset += 10240  # Skip ahead a bit
        
        # Scan for AR archives (used in Debian packages)
        self.logger.info("Scanning for AR archives...")
        ar_matches = self._find_pattern(b'!<arch>\n')
        for offset in ar_matches:
            self.logger.info(f"Found potential AR archive at offset 0x{offset:x}")
            container_info = {
                'type': 'AR',
                'offset': offset,
                'path': self._extract_container(offset, 'ar')
            }
            containers.append(container_info)
        
        # Scan for ZIP archives
        self.logger.info("Scanning for ZIP archives...")
        zip_matches = self._find_pattern(b'PK\x03\x04')
        for offset in zip_matches:
            self.logger.info(f"Found potential ZIP archive at offset 0x{offset:x}")
            container_info = {
                'type': 'ZIP',
                'offset': offset,
                'path': self._extract_container(offset, 'zip')
            }
            containers.append(container_info)
            
        # Create summary file
        summary_path = os.path.join(self.extraction_dir, "container_summary.json")
        with open(summary_path, 'w') as f:
            json.dump({
                "firmware_size": len(self.firmware_data),
                "containers": containers
            }, f, indent=2)
            
        return containers
    
    def _extract_container(self, offset: int, container_type: str) -> str:
        """Extract a container/archive from firmware data
        
        Args:
            offset: Offset of container in firmware
            container_type: Type of container
            
        Returns:
            Path to extracted container
        """
        # Size estimation is tricky for containers
        # For a real implementation, we would parse the format properly
        
        # For now, we'll extract a reasonable chunk or until the end of file
        size = len(self.firmware_data) - offset
        
        # Limit to a reasonable size for each type
        if container_type == 'cpio':
            size = min(50 * 1024 * 1024, size)  # 50MB max
        elif container_type == 'tar':
            size = min(100 * 1024 * 1024, size)  # 100MB max
        elif container_type == 'ar':
            size = min(20 * 1024 * 1024, size)  # 20MB max
        elif container_type == 'zip':
            # For ZIP, try to find the end marker
            end_offset = self.firmware_data.find(b'PK\x05\x06', offset)
            if end_offset != -1:
                # End marker found, add a small buffer
                size = (end_offset - offset) + 22  # Add space for end of central directory record
                size = min(size + 1024, len(self.firmware_data) - offset)  # Add a small buffer
            else:
                size = min(50 * 1024 * 1024, size)  # 50MB max
        
        container_data = self.firmware_data[offset:offset+size]
        output_path = os.path.join(self.extraction_dir, f"{container_type}_{offset:x}")
        
        with open(output_path, 'wb') as f:
            f.write(container_data)
            
        return output_path
    
    def extract_container_contents(self, container_path: str, container_type: str) -> List[str]:
        """Extract contents of a container/archive
        
        Args:
            container_path: Path to container file
            container_type: Type of container ('tar', 'cpio', 'ar', 'zip')
            
        Returns:
            List of paths to extracted files
        """
        import tempfile
        import shutil
        
        # Create output directory for container contents
        output_dir = f"{container_path}_contents"
        os.makedirs(output_dir, exist_ok=True)
        
        extracted_files = []
        
        try:
            if container_type == 'tar':
                import tarfile
                with tarfile.open(container_path, 'r') as tar:
                    # Extract all files
                    tar.extractall(path=output_dir)
                    extracted_files = [os.path.join(output_dir, name) for name in tar.getnames()]
                    
            elif container_type == 'cpio':
                # CPIO extraction requires external tools
                import subprocess
                
                # Create temp directory for extraction
                with tempfile.TemporaryDirectory() as temp_dir:
                    # Change to temp directory (cpio extracts to current dir)
                    original_dir = os.getcwd()
                    os.chdir(temp_dir)
                    
                    # Run cpio command
                    try:
                        subprocess.run(['cpio', '-i', '-F', container_path], 
                                      check=False, stderr=subprocess.PIPE)
                    except FileNotFoundError:
                        self.logger.error("cpio command not found, cannot extract cpio archive")
                    
                    # Copy extracted files to output directory
                    for root, _, files in os.walk('.'):
                        for file in files:
                            src_path = os.path.join(root, file)
                            rel_path = os.path.relpath(src_path, '.')
                            dst_path = os.path.join(output_dir, rel_path)
                            
                            os.makedirs(os.path.dirname(dst_path), exist_ok=True)
                            shutil.copy2(src_path, dst_path)
                            extracted_files.append(dst_path)
                    
                    # Change back to original directory
                    os.chdir(original_dir)
                    
            elif container_type == 'ar':
                # AR extraction requires external tools
                import subprocess
                
                try:
                    subprocess.run(['ar', 'x', container_path], 
                                  cwd=output_dir, check=False, stderr=subprocess.PIPE)
                    
                    # Get list of extracted files
                    extracted_files = [os.path.join(output_dir, f) for f in os.listdir(output_dir)]
                except FileNotFoundError:
                    self.logger.error("ar command not found, cannot extract ar archive")
                    
            elif container_type == 'zip':
                import zipfile
                
                with zipfile.ZipFile(container_path, 'r') as zip_ref:
                    zip_ref.extractall(output_dir)
                    extracted_files = [os.path.join(output_dir, name) for name in zip_ref.namelist()]
                    
            self.logger.info(f"Extracted {len(extracted_files)} files from {container_type} archive to {output_dir}")
            return extracted_files
            
        except Exception as e:
            self.logger.error(f"Error extracting {container_type} archive: {e}")
            return []
    
    def scan_for_compressed_data(self) -> List[Dict[str, Any]]:
        """Scan firmware for compressed data
        
        Returns:
            List of dictionaries with compressed data information
        """
        if not self.firmware_data:
            if not self.load_firmware():
                return []
        
        # Create extraction directory if needed
        os.makedirs(self.extraction_dir, exist_ok=True)
        
        # Results list
        compressed_areas = []
        
        # Scan for gzip data
        self.logger.info("Scanning for gzip compressed data...")
        gzip_matches = self._find_pattern(b'\x1F\x8B\x08')  # gzip magic + deflate
        for offset in gzip_matches:
            self.logger.info(f"Found potential gzip data at offset 0x{offset:x}")
            
            # Try to determine compressed data size
            size = self._determine_compressed_size(offset, 'gzip')
            
            if size:
                compressed_info = {
                    'type': 'gzip',
                    'offset': offset,
                    'size': size,
                    'path': self._extract_compressed_data(offset, size, 'gzip')
                }
                compressed_areas.append(compressed_info)
        
        # Scan for zlib data
        self.logger.info("Scanning for zlib compressed data...")
        # zlib header: 0x78 followed by 0x01, 0x5E, 0x9C, or 0xDA
        for first_byte in [b'\x78\x01', b'\x78\x5E', b'\x78\x9C', b'\x78\xDA']:
            zlib_matches = self._find_pattern(first_byte)
            for offset in zlib_matches:
                self.logger.info(f"Found potential zlib data at offset 0x{offset:x}")
                
                # Try to determine compressed data size
                size = self._determine_compressed_size(offset, 'zlib')
                
                if size:
                    compressed_info = {
                        'type': 'zlib',
                        'offset': offset,
                        'size': size,
                        'path': self._extract_compressed_data(offset, size, 'zlib')
                    }
                    compressed_areas.append(compressed_info)
        
        # Scan for bzip2 data
        self.logger.info("Scanning for bzip2 compressed data...")
        bzip2_matches = self._find_pattern(b'BZh')
        for offset in bzip2_matches:
            self.logger.info(f"Found potential bzip2 data at offset 0x{offset:x}")
            
            # Try to determine compressed data size
            size = self._determine_compressed_size(offset, 'bzip2')
            
            if size:
                compressed_info = {
                    'type': 'bzip2',
                    'offset': offset,
                    'size': size,
                    'path': self._extract_compressed_data(offset, size, 'bzip2')
                }
                compressed_areas.append(compressed_info)
        
        # Create summary file
        summary_path = os.path.join(self.extraction_dir, "compressed_summary.json")
        with open(summary_path, 'w') as f:
            json.dump({
                "firmware_size": len(self.firmware_data),
                "compressed_areas": compressed_areas
            }, f, indent=2)
            
        return compressed_areas
    
    def _determine_compressed_size(self, offset: int, comp_type: str) -> int:
        """Try to determine the size of compressed data
        
        Args:
            offset: Offset of compressed data
            comp_type: Type of compression
            
        Returns:
            Size of compressed data in bytes
        """
        # This is a heuristic approach - in a real implementation,
        # we would try to parse the compression format properly
        
        # For gzip, look for the trailer
        if comp_type == 'gzip':
            # Look for potential gzip end markers within a reasonable distance
            end_offset = -1
            for i in range(offset + 18, min(offset + 10 * 1024 * 1024, len(self.firmware_data) - 8)):
                # Check for another gzip magic header
                if self.firmware_data[i:i+3] == b'\x1F\x8B\x08':
                    end_offset = i
                    break
            
            if end_offset != -1:
                return end_offset - offset
            else:
                return min(1 * 1024 * 1024, len(self.firmware_data) - offset)  # 1MB max
                
        # For other formats, estimate a reasonable size
        elif comp_type in ['zlib', 'bzip2']:
            # Look for another instance of the same header
            if comp_type == 'zlib':
                patterns = [b'\x78\x01', b'\x78\x5E', b'\x78\x9C', b'\x78\xDA']
            elif comp_type == 'bzip2':
                patterns = [b'BZh']
                
            end_offset = -1
            for pattern in patterns:
                next_offset = self.firmware_data.find(pattern, offset + len(pattern))
                if next_offset > offset:
                    if end_offset == -1 or next_offset < end_offset:
                        end_offset = next_offset
            
            if end_offset != -1:
                return end_offset - offset
            else:
                return min(1 * 1024 * 1024, len(self.firmware_data) - offset)  # 1MB max
    
    def _extract_compressed_data(self, offset: int, size: int, comp_type: str) -> str:
        """Extract compressed data from firmware
        
        Args:
            offset: Offset of compressed data
            size: Size of compressed data
            comp_type: Type of compression
            
        Returns:
            Path to extracted compressed data
        """
        comp_data = self.firmware_data[offset:offset+size]
        output_path = os.path.join(self.extraction_dir, f"{comp_type}_{offset:x}")
        
        with open(output_path, 'wb') as f:
            f.write(comp_data)
            
        return output_path
    
    def decompress_data(self, compressed_path: str, comp_type: str) -> Optional[str]:
        """Decompress compressed data
        
        Args:
            compressed_path: Path to compressed data
            comp_type: Type of compression
            
        Returns:
            Path to decompressed data or None if decompression failed
        """
        import tempfile
        
        # Output path for decompressed data
        decompressed_path = f"{compressed_path}.decompressed"
        
        try:
            if comp_type == 'gzip':
                import gzip
                with gzip.open(compressed_path, 'rb') as f_in:
                    with open(decompressed_path, 'wb') as f_out:
                        f_out.write(f_in.read())
                        
            elif comp_type == 'zlib':
                import zlib
                with open(compressed_path, 'rb') as f_in:
                    with open(decompressed_path, 'wb') as f_out:
                        f_out.write(zlib.decompress(f_in.read()))
                        
            elif comp_type == 'bzip2':
                import bz2
                with bz2.open(compressed_path, 'rb') as f_in:
                    with open(decompressed_path, 'wb') as f_out:
                        f_out.write(f_in.read())
            
            self.logger.info(f"Decompressed {comp_type} data to {decompressed_path}")
            return decompressed_path
            
        except Exception as e:
            self.logger.error(f"Error decompressing {comp_type} data: {e}")
            return None

# ...existing code...
