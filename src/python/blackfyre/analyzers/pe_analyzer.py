"""Windows PE file analyzer for Blackfyre"""

import os
import re
import json
import struct
import logging
import datetime
import hashlib
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any, Union, Iterator
from blackfyre.datatypes.contexts.binarycontext import BinaryContext

# PE file constants
IMAGE_DOS_SIGNATURE = 0x5A4D      # MZ
IMAGE_NT_SIGNATURE = 0x00004550   # PE\0\0
IMAGE_FILE_MACHINE_I386 = 0x014c
IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_MACHINE_ARM = 0x01c0
IMAGE_FILE_MACHINE_ARM64 = 0xAA64
IMAGE_DIRECTORY_ENTRY_EXPORT = 0
IMAGE_DIRECTORY_ENTRY_IMPORT = 1
IMAGE_DIRECTORY_ENTRY_RESOURCE = 2
IMAGE_DIRECTORY_ENTRY_SECURITY = 4
IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
IMAGE_DIRECTORY_ENTRY_DEBUG = 6
IMAGE_DIRECTORY_ENTRY_TLS = 9
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10

class PEAnalyzer:
    """Analyzer for Windows PE files"""
    
    def __init__(self, 
                 pe_path: str,
                 extraction_dir: Optional[str] = None):
        """Initialize the PE analyzer
        
        Args:
            pe_path: Path to PE file
            extraction_dir: Directory to extract resources and other data
        """
        self.pe_path = pe_path
        
        # Validate PE path
        if not os.path.exists(pe_path):
            raise FileNotFoundError(f"PE file not found: {pe_path}")
            
        # Set up extraction directory
        if extraction_dir:
            self.extraction_dir = Path(extraction_dir)
        else:
            # Default extraction directory next to PE file
            parent = Path(pe_path).parent
            base_name = Path(pe_path).stem
            self.extraction_dir = parent / f"{base_name}_pe_analysis"
            
        self.logger = logging.getLogger(__name__)
        
        # PE data
        self.pe_data = None
        self.is_valid_pe = False
        self.dos_header = {}
        self.nt_headers = {}
        self.file_header = {}
        self.optional_header = {}
        self.sections = []
        self.imports = []
        self.exports = []
        self.resources = []
        self.tls_callbacks = []
        self.debug_info = []
        self.load_config = {}
        self.security_info = {}
        self.certificates = []
        
        # Analysis results
        self.anomalies = []
        self.security_issues = []
    
    def load_pe(self) -> bool:
        """Load PE file data
        
        Returns:
            True if successfully loaded
        """
        try:
            with open(self.pe_path, 'rb') as f:
                self.pe_data = f.read()
            self.logger.info(f"Loaded {len(self.pe_data)} bytes from {self.pe_path}")
            return True
        except Exception as e:
            self.logger.error(f"Error loading PE file: {e}")
            return False
    
    def analyze(self) -> Dict[str, Any]:
        """Analyze PE file
        
        Returns:
            Dictionary with analysis results
        """
        if not self.pe_data:
            if not self.load_pe():
                return {}
                
        # Create extraction directory
        os.makedirs(self.extraction_dir, exist_ok=True)
        
        # Parse PE headers
        if not self._parse_headers():
            return {"error": "Invalid PE file"}
            
        # Parse sections
        self._parse_sections()
        
        # Parse imports
        self._parse_imports()
        
        # Parse exports
        self._parse_exports()
        
        # Parse resources
        self._parse_resources()
        
        # Parse security information
        self._parse_security_info()
        
        # Check for anomalies and security issues
        self._check_for_anomalies()
        
        # Collect results
        results = {
            "file_info": {
                "name": os.path.basename(self.pe_path),
                "size": len(self.pe_data),
                "md5": hashlib.md5(self.pe_data).hexdigest(),
                "sha1": hashlib.sha1(self.pe_data).hexdigest(),
                "sha256": hashlib.sha256(self.pe_data).hexdigest()
            },
            "headers": {
                "dos_header": self.dos_header,
                "file_header": self.file_header,
                "optional_header": self.optional_header
            },
            "sections": self.sections,
            "imports": self.imports,
            "exports": self.exports,
            "resources": self.resources,
            "tls_callbacks": self.tls_callbacks,
            "security_info": self.security_info,
            "anomalies": self.anomalies,
            "security_issues": self.security_issues
        }
        
        # Write results to JSON file
        output_path = os.path.join(self.extraction_dir, "pe_analysis.json")
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2, default=str)
            
        return results
    
    def _parse_headers(self) -> bool:
        """Parse PE headers
        
        Returns:
            True if valid PE file
        """
        # Check minimum size
        if len(self.pe_data) < 64:
            self.logger.error("File too small to be a PE file")
            return False
            
        # Parse DOS header
        dos_sig = struct.unpack('<H', self.pe_data[0:2])[0]
        
        if dos_sig != IMAGE_DOS_SIGNATURE:
            self.logger.error("Invalid DOS signature")
            return False
            
        # Get PE header offset
        pe_offset = struct.unpack('<I', self.pe_data[60:64])[0]
        
        # Validate PE offset
        if pe_offset >= len(self.pe_data) or pe_offset < 64:
            self.logger.error(f"Invalid PE offset: {pe_offset}")
            return False
            
        # Check PE signature
        pe_sig = struct.unpack('<I', self.pe_data[pe_offset:pe_offset+4])[0]
        
        if pe_sig != IMAGE_NT_SIGNATURE:
            self.logger.error("Invalid PE signature")
            return False
            
        # Parse DOS header
        self.dos_header = {
            'e_magic': dos_sig,
            'e_lfanew': pe_offset
        }
        
        # Parse file header
        file_header_offset = pe_offset + 4
        
        # Check if we have enough data
        if file_header_offset + 20 > len(self.pe_data):
            self.logger.error("Not enough data for FILE_HEADER")
            return False
            
        # Parse file header fields
        machine, num_sections, time_date_stamp, ptr_symtab, num_symbols, opt_header_size, characteristics = \
            struct.unpack('<HHIIIHH', self.pe_data[file_header_offset:file_header_offset+20])
            
        # Convert timestamp to readable format
        time_date = datetime.datetime.fromtimestamp(time_date_stamp)
        
        self.file_header = {
            'Machine': machine,
            'NumberOfSections': num_sections,
            'TimeDateStamp': time_date_stamp,
            'TimeDateString': time_date.strftime('%Y-%m-%d %H:%M:%S'),
            'PointerToSymbolTable': ptr_symtab,
            'NumberOfSymbols': num_symbols,
            'SizeOfOptionalHeader': opt_header_size,
            'Characteristics': characteristics,
            'Machine_Type': self._get_machine_type(machine)
        }
        
        # Parse optional header
        opt_header_offset = file_header_offset + 20
        
        # Check if we have enough data
        if opt_header_offset + 2 > len(self.pe_data):
            self.logger.error("Not enough data for OPTIONAL_HEADER magic")
            return False
            
        # Check optional header magic
        magic = struct.unpack('<H', self.pe_data[opt_header_offset:opt_header_offset+2])[0]
        
        if magic == 0x10b:  # PE32
            self.optional_header['Magic'] = "PE32"
            if opt_header_offset + 96 > len(self.pe_data):
                self.logger.error("Not enough data for PE32 OPTIONAL_HEADER")
                return False
                
            # Parse PE32 optional header
            oh_fields = struct.unpack('<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII',
                self.pe_data[opt_header_offset:opt_header_offset+96])
                
            self.optional_header.update({
                'MajorLinkerVersion': oh_fields[1],
                'MinorLinkerVersion': oh_fields[2],
                'SizeOfCode': oh_fields[3],
                'SizeOfInitializedData': oh_fields[4],
                'SizeOfUninitializedData': oh_fields[5],
                'AddressOfEntryPoint': oh_fields[6],
                'BaseOfCode': oh_fields[7],
                'BaseOfData': oh_fields[8],
                'ImageBase': oh_fields[9],
                'SectionAlignment': oh_fields[10],
                'FileAlignment': oh_fields[11],
                'MajorOperatingSystemVersion': oh_fields[12],
                'MinorOperatingSystemVersion': oh_fields[13],
                'MajorImageVersion': oh_fields[14],
                'MinorImageVersion': oh_fields[15],
                'MajorSubsystemVersion': oh_fields[16],
                'MinorSubsystemVersion': oh_fields[17],
                'Win32VersionValue': oh_fields[18],
                'SizeOfImage': oh_fields[19],
                'SizeOfHeaders': oh_fields[20],
                'CheckSum': oh_fields[21],
                'Subsystem': oh_fields[22],
                'DllCharacteristics': oh_fields[23]
            })
            
            # Data directories start at offset 96 + opt_header_offset
            data_dir_offset = opt_header_offset + 96
            
        elif magic == 0x20b:  # PE32+
            self.optional_header['Magic'] = "PE32+"
            if opt_header_offset + 112 > len(self.pe_data):
                self.logger.error("Not enough data for PE32+ OPTIONAL_HEADER")
                return False
                
            # Parse PE32+ optional header
            oh_fields = struct.unpack('<HBBIIIIIIIIIIHHHHHHIIIIHHQQQQII',
                self.pe_data[opt_header_offset:opt_header_offset+112])
                
            self.optional_header.update({
                'MajorLinkerVersion': oh_fields[1],
                'MinorLinkerVersion': oh_fields[2],
                'SizeOfCode': oh_fields[3],
                'SizeOfInitializedData': oh_fields[4],
                'SizeOfUninitializedData': oh_fields[5],
                'AddressOfEntryPoint': oh_fields[6],
                'BaseOfCode': oh_fields[7],
                'ImageBase': oh_fields[8],
                'SectionAlignment': oh_fields[9],
                'FileAlignment': oh_fields[10],
                'MajorOperatingSystemVersion': oh_fields[11],
                'MinorOperatingSystemVersion': oh_fields[12],
                'MajorImageVersion': oh_fields[13],
                'MinorImageVersion': oh_fields[14],
                'MajorSubsystemVersion': oh_fields[15],
                'MinorSubsystemVersion': oh_fields[16],
                'Win32VersionValue': oh_fields[17],
                'SizeOfImage': oh_fields[18],
                'SizeOfHeaders': oh_fields[19],
                'CheckSum': oh_fields[20],
                'Subsystem': oh_fields[21],
                'DllCharacteristics': oh_fields[22]
            })
            
            # Data directories start at offset 112 + opt_header_offset
            data_dir_offset = opt_header_offset + 112
        else:
            self.logger.error(f"Unknown OPTIONAL_HEADER magic: {magic:#x}")
            return False
            
        # Parse data directories
        self.data_directories = []
        for i in range(16):  # Maximum 16 data directories
            if data_dir_offset + 8 > len(self.pe_data):
                break
                
            rva, size = struct.unpack('<II', self.pe_data[data_dir_offset:data_dir_offset+8])
            self.data_directories.append({'RVA': rva, 'Size': size})
            data_dir_offset += 8
            
        self.optional_header['DataDirectory'] = self.data_directories
        
        # Set flag indicating this is a valid PE file
        self.is_valid_pe = True
        return True
    
    def _parse_sections(self):
        """Parse PE section headers"""
        if not self.is_valid_pe:
            return
            
        # Calculate section header offset
        pe_offset = self.dos_header['e_lfanew']
        section_offset = pe_offset + 4 + 20 + self.file_header['SizeOfOptionalHeader']
        
        # Parse each section header
        for i in range(self.file_header['NumberOfSections']):
            # Check if we have enough data
            if section_offset + 40 > len(self.pe_data):
                break
                
            # Parse section header
            name_bytes = self.pe_data[section_offset:section_offset+8]
            name = name_bytes.rstrip(b'\x00').decode('utf-8', errors='replace')
            
            virtual_size, virtual_address, size_of_raw_data, pointer_to_raw_data, \
                pointer_to_relocs, pointer_to_linenums, num_relocs, num_linenums, characteristics = \
                struct.unpack('<IIIIIIHHI', self.pe_data[section_offset+8:section_offset+40])
                
            section = {
                'Name': name,
                'VirtualSize': virtual_size,
                'VirtualAddress': virtual_address,
                'SizeOfRawData': size_of_raw_data,
                'PointerToRawData': pointer_to_raw_data,
                'Characteristics': characteristics,
                'Entropy': self._calculate_entropy(pointer_to_raw_data, size_of_raw_data)
            }
            
            self.sections.append(section)
            section_offset += 40
    
    def _parse_imports(self):
        """Parse PE import directory"""
        if not self.is_valid_pe or len(self.data_directories) <= IMAGE_DIRECTORY_ENTRY_IMPORT:
            return
            
        import_dir = self.data_directories[IMAGE_DIRECTORY_ENTRY_IMPORT]
        
        # Check if import directory exists
        if import_dir['RVA'] == 0 or import_dir['Size'] == 0:
            return
            
        # Convert RVA to file offset
        import_offset = self._rva_to_file_offset(import_dir['RVA'])
        
        if import_offset is None:
            return
            
        # Parse import descriptors
        offset = import_offset
        
        while True:
            # Check if we have enough data
            if offset + 20 > len(self.pe_data):
                break
                
            # Parse import descriptor
            orig_first_thunk, time_date_stamp, forwarder_chain, name_rva, first_thunk = \
                struct.unpack('<IIIII', self.pe_data[offset:offset+20])
                
            # Check if we've reached the end of the import descriptors
            if orig_first_thunk == 0 and name_rva == 0 and first_thunk == 0:
                break
                
            # Get DLL name
            name_offset = self._rva_to_file_offset(name_rva)
            
            if name_offset is None:
                offset += 20
                continue
                
            # Read DLL name
            dll_name = self._read_c_string(name_offset)
            
            # Process import functions
            import_entry = {
                'DLL': dll_name,
                'Functions': []
            }
            
            # Use OriginalFirstThunk if available, otherwise use FirstThunk
            thunk_rva = orig_first_thunk if orig_first_thunk != 0 else first_thunk
            thunk_offset = self._rva_to_file_offset(thunk_rva)
            
            if thunk_offset is not None:
                is_64bit = self.optional_header['Magic'] == "PE32+"
                thunk_size = 8 if is_64bit else 4
                
                thunk_idx = 0
                while True:
                    # Check if we have enough data
                    if thunk_offset + thunk_size > len(self.pe_data):
                        break
                        
                    # Read thunk value
                    if is_64bit:
                        thunk_value = struct.unpack('<Q', self.pe_data[thunk_offset:thunk_offset+8])[0]
                    else:
                        thunk_value = struct.unpack('<I', self.pe_data[thunk_offset:thunk_offset+4])[0]
                        
                    # Check if we've reached the end of the thunk array
                    if thunk_value == 0:
                        break
                        
                    # Get function information
                    func_info = {}
                    
                    # Check if import by ordinal
                    if is_64bit and (thunk_value & 0x8000000000000000):
                        ordinal = thunk_value & 0xFFFF
                        func_info = {
                            'Ordinal': ordinal,
                            'Name': f"Ordinal_{ordinal}",
                            'Hint': None
                        }
                    elif not is_64bit and (thunk_value & 0x80000000):
                        ordinal = thunk_value & 0xFFFF
                        func_info = {
                            'Ordinal': ordinal,
                            'Name': f"Ordinal_{ordinal}",
                            'Hint': None
                        }
                    else:
                        # Import by name
                        name_rva = thunk_value & (0x7FFFFFFFFFFFFFFF if is_64bit else 0x7FFFFFFF)
                        name_offset = self._rva_to_file_offset(name_rva)
                        
                        if name_offset is not None and name_offset + 2 < len(self.pe_data):
                            # Read hint value
                            hint = struct.unpack('<H', self.pe_data[name_offset:name_offset+2])[0]
                            
                            # Read function name
                            func_name = self._read_c_string(name_offset + 2)
                            
                            func_info = {
                                'Ordinal': None,
                                'Name': func_name,
                                'Hint': hint
                            }
                    
                    import_entry['Functions'].append(func_info)
                    thunk_offset += thunk_size
                    thunk_idx += 1
            
            self.imports.append(import_entry)
            offset += 20
    
    def _parse_exports(self):
        """Parse PE export directory"""
        if not self.is_valid_pe or len(self.data_directories) <= IMAGE_DIRECTORY_ENTRY_EXPORT:
            return
            
        export_dir = self.data_directories[IMAGE_DIRECTORY_ENTRY_EXPORT]
        
        # Check if export directory exists
        if export_dir['RVA'] == 0 or export_dir['Size'] == 0:
            return
            
        # Convert RVA to file offset
        export_offset = self._rva_to_file_offset(export_dir['RVA'])
        
        if export_offset is None or export_offset + 40 > len(self.pe_data):
            return
            
        # Parse export directory
        characteristics, time_date_stamp, major_version, minor_version, \
            name_rva, ordinal_base, num_functions, num_names, addr_func_rva, \
            addr_name_rva, addr_ordinal_rva = \
            struct.unpack('<IIIHHHIIIII', self.pe_data[export_offset:export_offset+40])
            
        # Get DLL name
        name_offset = self._rva_to_file_offset(name_rva)
        dll_name = self._read_c_string(name_offset) if name_offset is not None else ""
        
        # Get function address table
        addr_func_offset = self._rva_to_file_offset(addr_func_rva)
        addr_name_offset = self._rva_to_file_offset(addr_name_rva)
        addr_ordinal_offset = self._rva_to_file_offset(addr_ordinal_rva)
        
        if None in (addr_func_offset, addr_name_offset, addr_ordinal_offset):
            return
            
        # Parse export functions
        export_info = {
            'DLL': dll_name,
            'OrdinalBase': ordinal_base,
            'Functions': []
        }
        
        # Process functions with names
        for i in range(num_names):
            # Check if we have enough data
            if addr_name_offset + 4 > len(self.pe_data) or addr_ordinal_offset + 2 > len(self.pe_data):
                break
                
            # Get function name RVA
            name_rva = struct.unpack('<I', self.pe_data[addr_name_offset:addr_name_offset+4])[0]
            
            # Get function ordinal
            ordinal = struct.unpack('<H', self.pe_data[addr_ordinal_offset:addr_ordinal_offset+2])[0]
            
            # Get function RVA
            if addr_func_offset + (ordinal * 4) + 4 > len(self.pe_data):
                break
                
            func_rva = struct.unpack('<I', self.pe_data[addr_func_offset+(ordinal*4):addr_func_offset+(ordinal*4)+4])[0]
            
            # Get function name
            name_offset = self._rva_to_file_offset(name_rva)
            func_name = self._read_c_string(name_offset) if name_offset is not None else f"Func_{ordinal}"
            
            func_info = {
                'Name': func_name,
                'Ordinal': ordinal + ordinal_base,
                'RVA': func_rva
            }
            
            export_info['Functions'].append(func_info)
            
            addr_name_offset += 4
            addr_ordinal_offset += 2
            
        # Process functions without names
        for i in range(num_functions):
            # Check if this ordinal already has an entry with a name
            ordinal = i
            
            if any(func['Ordinal'] == ordinal + ordinal_base for func in export_info['Functions']):
                continue
                
            # Get function RVA
            if addr_func_offset + (ordinal * 4) + 4 > len(self.pe_data):
                break
                
            func_rva = struct.unpack('<I', self.pe_data[addr_func_offset+(ordinal*4):addr_func_offset+(ordinal*4)+4])[0]
            
            if func_rva == 0:
                continue
                
            func_info = {
                'Name': f"Ordinal_{ordinal + ordinal_base}",
                'Ordinal': ordinal + ordinal_base,
                'RVA': func_rva
            }
            
            export_info['Functions'].append(func_info)
            
        self.exports = export_info
    
    def _parse_resources(self):
        """Parse PE resource directory"""
        if not self.is_valid_pe or len(self.data_directories) <= IMAGE_DIRECTORY_ENTRY_RESOURCE:
            return
            
        resource_dir = self.data_directories[IMAGE_DIRECTORY_ENTRY_RESOURCE]
        
        # Check if resource directory exists
        if resource_dir['RVA'] == 0 or resource_dir['Size'] == 0:
            return
            
        # Convert RVA to file offset
        resource_offset = self._rva_to_file_offset(resource_dir['RVA'])
        
        if resource_offset is None:
            return
            
        # We'd need to recursively parse the resource directory structure here
        # This is a complex task beyond the scope of this example
        # For now, just record the existence of resources
        self.resources = {
            'DirectoryRVA': resource_dir['RVA'],
            'Size': resource_dir['Size']
        }
    
    def _parse_security_info(self):
        """Parse PE security directory (certificates)"""
        if not self.is_valid_pe or len(self.data_directories) <= IMAGE_DIRECTORY_ENTRY_SECURITY:
            return
            
        security_dir = self.data_directories[IMAGE_DIRECTORY_ENTRY_SECURITY]
        
        # Check if security directory exists
        if security_dir['RVA'] == 0 or security_dir['Size'] == 0:
            return
            
        # The security directory is special: RVA is actually a raw file offset
        offset = security_dir['RVA']
        
        if offset >= len(self.pe_data):
            return
            
        # Parse WIN_CERTIFICATE structure
        if offset + 8 > len(self.pe_data):
            return
            
        length, revision, cert_type = struct.unpack('<IHH', self.pe_data[offset:offset+8])
        
        self.security_info = {
            'Length': length,
            'Revision': revision,
            'Type': cert_type,
            'Certificate': {
                'Offset': offset + 8,
                'Size': length - 8 if length > 8 else 0
            }
        }
        
        # Extract certificate if size is reasonable
        if 8 < length < 10*1024*1024 and offset + length <= len(self.pe_data):
            cert_data = self.pe_data[offset+8:offset+length]
            cert_file = os.path.join(self.extraction_dir, "certificate.der")
            
            with open(cert_file, 'wb') as f:
                f.write(cert_data)
                
            self.security_info['Certificate']['Path'] = cert_file
    
    def _check_for_anomalies(self):
        """Check for anomalies and security issues in the PE file"""
        # Check for known indicators of potentially malicious files
        
        # 1. Check section names
        suspicious_section_names = {'.evil', '.hack', '.viru', 'UPX', 'nsp0', '.aspack', '.adata'}
        for section in self.sections:
            if section['Name'] in suspicious_section_names:
                self.anomalies.append({
                    'type': 'suspicious_section',
                    'description': f"Suspicious section name: {section['Name']}",
                    'severity': 'medium'
                })
                
        # 2. Check for high entropy sections (potential encryption/packing)
        for section in self.sections:
            if section.get('Entropy', 0) > 7.5:
                self.anomalies.append({
                    'type': 'high_entropy',
                    'description': f"High entropy section: {section['Name']} (entropy: {section['Entropy']:.2f})",
                    'severity': 'medium'
                })
                
        # 3. Check for suspicious imports
        suspicious_apis = {
            'WriteProcessMemory', 'ReadProcessMemory', 'CreateRemoteThread',
            'VirtualAllocEx', 'SetWindowsHookEx', 'GetAsyncKeyState',
            'GetKeyState', 'MapVirtualKey', 'FindWindow'
        }
        
        for lib in self.imports:
            for func in lib['Functions']:
                if func['Name'] in suspicious_apis:
                    self.security_issues.append({
                        'type': 'suspicious_api',
                        'description': f"Suspicious API import: {lib['DLL']}!{func['Name']}",
                        'severity': 'medium'
                    })
                    
        # 4. Check for discrepancies in file header
        if 'TimeDateStamp' in self.file_header:
            # Check for very old or future timestamps
            timestamp = self.file_header['TimeDateStamp']
            current_time = int(datetime.datetime.now().timestamp())
            
            if timestamp > current_time:
                self.anomalies.append({
                    'type': 'future_timestamp',
                    'description': f"PE file has a future timestamp: {self.file_header['TimeDateString']}",
                    'severity': 'low'
                })
            elif timestamp < 946684800:  # 2000-01-01
                self.anomalies.append({
                    'type': 'old_timestamp',
                    'description': f"PE file has a very old timestamp: {self.file_header['TimeDateString']}",
                    'severity': 'low'
                })
                
        # 5. Check for missing or invalid signature
        if not self.security_info:
            self.anomalies.append({
                'type': 'unsigned',
                'description': "PE file is not digitally signed",
                'severity': 'low'
            })
    
    def _get_machine_type(self, machine: int) -> str:
        """Get human-readable machine type
        
        Args:
            machine: Machine type code
            
        Returns:
            Human-readable machine type
        """
        machine_types = {
            IMAGE_FILE_MACHINE_I386: "x86",
            IMAGE_FILE_MACHINE_AMD64: "x64",
            IMAGE_FILE_MACHINE_ARM: "ARM",
            IMAGE_FILE_MACHINE_ARM64: "ARM64"
        }
        return machine_types.get(machine, f"Unknown ({machine:#x})")
    
    def _rva_to_file_offset(self, rva: int) -> Optional[int]:
        """Convert RVA to file offset
        
        Args:
            rva: Relative Virtual Address
            
        Returns:
            File offset or None if RVA is invalid
        """
        # Find section containing the RVA
        for section in self.sections:
            if section['VirtualAddress'] <= rva < section['VirtualAddress'] + section['VirtualSize']:
                return section['PointerToRawData'] + (rva - section['VirtualAddress'])
                
        return None
    
    def _read_c_string(self, offset: int) -> str:
        """Read null-terminated C string from file
        
        Args:
            offset: File offset
            
        Returns:
            String value or empty string if invalid offset
        """
        if offset >= len(self.pe_data):
            return ""
            
        # Find null terminator
        end = offset
        while end < len(self.pe_data) and self.pe_data[end] != 0:
            end += 1
            
        # Extract string
        return self.pe_data[offset:end].decode('utf-8', errors='replace')
    
    def _calculate_entropy(self, offset: int, size: int) -> float:
        """Calculate entropy of data
        
        Args:
            offset: File offset
            size: Data size
            
        Returns:
            Entropy value (0-8)
        """
        if offset >= len(self.pe_data) or size <= 0 or offset + size > len(self.pe_data):
            return 0
            
        # Get data
        data = self.pe_data[offset:offset+size]
        
        # Count byte frequencies
        byte_count = {}
        for byte in data:
            byte_count[byte] = byte_count.get(byte, 0) + 1
            
        # Calculate entropy
        entropy = 0
        for count in byte_count.values():
            p = count / size
            entropy -= p * (math.log(p) / math.log(256))
            
        return entropy * 8  # Scale to 0-8
    
    def generate_report(self, output_file: Optional[str] = None) -> str:
        """Generate PE analysis report
        
        Args:
            output_file: Path to save the report to
            
        Returns:
            Path to the generated report
        """
        # Run analysis if not already done
        if not self.is_valid_pe:
            self.analyze()
            
        # Create report directory
        report_dir = os.path.join(self.extraction_dir, "report")
        os.makedirs(report_dir, exist_ok=True)
        
        # Set default output file if not provided
        if not output_file:
            output_file = os.path.join(report_dir, "pe_analysis_report.md")
        
        # Generate report content
        report = f"""# PE File Analysis Report

## File Information

- **Filename:** {os.path.basename(self.pe_path)}
- **Size:** {len(self.pe_data)} bytes
- **MD5:** {hashlib.md5(self.pe_data).hexdigest()}
- **SHA-1:** {hashlib.sha1(self.pe_data).hexdigest()}
- **SHA-256:** {hashlib.sha256(self.pe_data).hexdigest()}
- **Type:** {self.optional_header.get('Magic', 'Unknown')}
- **Architecture:** {self.file_header.get('Machine_Type', 'Unknown')}
- **Timestamp:** {self.file_header.get('TimeDateString', 'Unknown')}

## Headers

- **Entry Point:** 0x{self.optional_header.get('AddressOfEntryPoint', 0):#x}
- **Image Base:** 0x{self.optional_header.get('ImageBase', 0):#x}
- **Subsystem:** {self.optional_header.get('Subsystem', 0)}
- **DLL Characteristics:** 0x{self.optional_header.get('DllCharacteristics', 0):#x}

## Sections

"""
        
        # Add sections
        for i, section in enumerate(self.sections, 1):
            report += f"### {i}. {section['Name']}\n\n"
            report += f"- **Virtual Address:** 0x{section['VirtualAddress']:#x}\n"
            report += f"- **Virtual Size:** {section['VirtualSize']} bytes\n"
            report += f"- **Raw Size:** {section['SizeOfRawData']} bytes\n"
            report += f"- **Characteristics:** 0x{section['Characteristics']:#x}\n"
            if 'Entropy' in section:
                report += f"- **Entropy:** {section['Entropy']:.2f}\n"
            report += "\n"
            
        # Add imports
        report += "## Imports\n\n"
        
        for lib in self.imports:
            report += f"### {lib['DLL']}\n\n"
            
            for func in lib['Functions'][:20]:  # Limit to 20 functions per library
                func_name = func['Name']
                if func['Ordinal'] is not None:
                    report += f"- {func_name} (Ordinal: {func['Ordinal']})\n"
                else:
                    report += f"- {func_name}\n"
                    
            if len(lib['Functions']) > 20:
                report += f"\n... and {len(lib['Functions']) - 20} more functions\n"
                
            report += "\n"
            
        # Add exports
        if hasattr(self.exports, 'get') and self.exports.get('Functions'):
            report += "## Exports\n\n"
            report += f"**DLL Name:** {self.exports.get('DLL', 'Unknown')}\n\n"
            
            for func in self.exports['Functions'][:20]:  # Limit to 20 functions
                report += f"- {func['Name']} (Ordinal: {func['Ordinal']}, RVA: 0x{func['RVA']:#x})\n"
                
            if len(self.exports['Functions']) > 20:
                report += f"\n... and {len(self.exports['Functions']) - 20} more functions\n"
                
            report += "\n"
            
        # Add security info
        if self.security_info:
            report += "## Security Information\n\n"
            report += f"- **Certificate Type:** {self.security_info.get('Type')}\n"
            report += f"- **Certificate Size:** {self.security_info.get('Certificate', {}).get('Size', 0)} bytes\n"
            
            if 'Path' in self.security_info.get('Certificate', {}):
                report += f"- **Certificate File:** {os.path.basename(self.security_info['Certificate']['Path'])}\n"
                
            report += "\n"
            
        # Add anomalies and security issues
        if self.anomalies or self.security_issues:
            report += "## Security Analysis\n\n"
            
            if self.anomalies:
                report += "### Anomalies\n\n"
                for anomaly in self.anomalies:
                    report += f"- [{anomaly['severity'].upper()}] {anomaly['description']}\n"
                report += "\n"
                
            if self.security_issues:
                report += "### Security Issues\n\n"
                for issue in self.security_issues:
                    report += f"- [{issue['severity'].upper()}] {issue['description']}\n"
                report += "\n"
                
        # Write report to file
        with open(output_file, 'w') as f:
            f.write(report)
            
        return output_file
