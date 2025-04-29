"""ELF file format support for Blackfyre"""

import struct
import ctypes
from enum import IntEnum
from typing import Dict, List, Tuple, Optional, Any, Iterator, BinaryIO

class ElfClass(IntEnum):
    """ELF file class"""
    ELFCLASSNONE = 0
    ELFCLASS32 = 1
    ELFCLASS64 = 2

class ElfData(IntEnum):
    """ELF data encoding"""
    ELFDATANONE = 0
    ELFDATA2LSB = 1  # Little-endian
    ELFDATA2MSB = 2  # Big-endian

class ElfType(IntEnum):
    """ELF file type"""
    ET_NONE = 0
    ET_REL = 1   # Relocatable file
    ET_EXEC = 2  # Executable file
    ET_DYN = 3   # Shared object file
    ET_CORE = 4  # Core dump file

class ElfMachine(IntEnum):
    """ELF machine type"""
    EM_NONE = 0
    EM_M32 = 1
    EM_SPARC = 2
    EM_386 = 3
    EM_68K = 4
    EM_88K = 5
    EM_860 = 7
    EM_MIPS = 8
    EM_ARM = 40
    EM_X86_64 = 62
    EM_AARCH64 = 183

class ElfSectionType(IntEnum):
    """ELF section type"""
    SHT_NULL = 0
    SHT_PROGBITS = 1
    SHT_SYMTAB = 2
    SHT_STRTAB = 3
    SHT_RELA = 4
    SHT_HASH = 5
    SHT_DYNAMIC = 6
    SHT_NOTE = 7
    SHT_NOBITS = 8
    SHT_REL = 9
    SHT_SHLIB = 10
    SHT_DYNSYM = 11

class ElfSectionFlags(IntEnum):
    """ELF section flags"""
    SHF_WRITE = 1
    SHF_ALLOC = 2
    SHF_EXECINSTR = 4
    SHF_MASKPROC = 0xf0000000

class ElfSegmentType(IntEnum):
    """ELF segment type"""
    PT_NULL = 0
    PT_LOAD = 1
    PT_DYNAMIC = 2
    PT_INTERP = 3
    PT_NOTE = 4
    PT_SHLIB = 5
    PT_PHDR = 6
    PT_TLS = 7

class ElfParser:
    """Parser for ELF files"""
    
    def __init__(self, file_path: Optional[str] = None, data: Optional[bytes] = None):
        """Initialize the ELF parser
        
        Args:
            file_path: Path to ELF file
            data: Raw ELF data
        """
        self.file_path = file_path
        self.data = data
        self.elf_header = {}
        self.section_headers = []
        self.program_headers = []
        self.symbols = []
        self.dynamic_symbols = []
        self.dynamic_entries = []
        self.string_table = {}
        self._file = None
        self._endian = '<'  # Default to little-endian
    
    def parse(self) -> Dict[str, Any]:
        """Parse the ELF file
        
        Returns:
            Dictionary with ELF information
        """
        if self.file_path:
            with open(self.file_path, 'rb') as f:
                self._file = f
                self._parse_file()
        elif self.data:
            import io
            self._file = io.BytesIO(self.data)
            self._parse_file()
        else:
            raise ValueError("Either file_path or data must be provided")
            
        return {
            "header": self.elf_header,
            "section_headers": self.section_headers,
            "program_headers": self.program_headers,
            "symbols": self.symbols,
            "dynamic_symbols": self.dynamic_symbols,
            "dynamic_entries": self.dynamic_entries,
        }
    
    def _parse_file(self):
        """Parse the ELF file"""
        self._parse_elf_header()
        self._parse_program_headers()
        self._parse_section_headers()
        self._parse_symbols()
    
    def _parse_elf_header(self):
        """Parse the ELF header"""
        self._file.seek(0)
        
        # Parse e_ident
        e_ident = self._file.read(16)
        
        # Verify ELF magic number
        if e_ident[:4] != b'\x7FELF':
            raise ValueError("Not a valid ELF file")
            
        # Parse basic header info
        self.elf_header = {
            "magic": e_ident[:4].hex(),
            "class": e_ident[4],
            "data": e_ident[5],
            "version": e_ident[6],
            "osabi": e_ident[7],
            "abiversion": e_ident[8],
        }
        
        # Set endianness based on ELF header
        self._endian = '<' if self.elf_header["data"] == ElfData.ELFDATA2LSB else '>'
        
        # Parse the rest of the header based on 32/64-bit
        if self.elf_header["class"] == ElfClass.ELFCLASS32:
            fmt = f"{self._endian}HHIIIIIHHHHHH"
            header_size = 52
            fields = struct.unpack(fmt, self._file.read(struct.calcsize(fmt)))
            
            self.elf_header.update({
                "type": fields[0],
                "machine": fields[1],
                "version": fields[2],
                "entry": fields[3],
                "phoff": fields[4],
                "shoff": fields[5],
                "flags": fields[6],
                "ehsize": fields[7],
                "phentsize": fields[8],
                "phnum": fields[9],
                "shentsize": fields[10],
                "shnum": fields[11],
                "shstrndx": fields[12],
                "is_64bit": False,
            })
        else:  # ELFCLASS64
            fmt = f"{self._endian}HHIQQQIHHHHHH"
            header_size = 64
            fields = struct.unpack(fmt, self._file.read(struct.calcsize(fmt)))
            
            self.elf_header.update({
                "type": fields[0],
                "machine": fields[1],
                "version": fields[2],
                "entry": fields[3],
                "phoff": fields[4],
                "shoff": fields[5],
                "flags": fields[6],
                "ehsize": fields[7],
                "phentsize": fields[8],
                "phnum": fields[9],
                "shentsize": fields[10],
                "shnum": fields[11],
                "shstrndx": fields[12],
                "is_64bit": True,
            })
    
    def _parse_section_headers(self):
        """Parse section headers"""
        is_64bit = self.elf_header["is_64bit"]
        shoff = self.elf_header["shoff"]
        shentsize = self.elf_header["shentsize"]
        shnum = self.elf_header["shnum"]
        
        self.section_headers = []
        
        # Read the section name string table first if available
        if self.elf_header["shstrndx"] < shnum:
            # Save current position
            current_pos = self._file.tell()
            
            # Read string table header
            shstrtab_offset = shoff + self.elf_header["shstrndx"] * shentsize
            self._file.seek(shstrtab_offset)
            
            if is_64bit:
                fmt = f"{self._endian}IIQQQQIIQQ"
                fields = struct.unpack(fmt, self._file.read(struct.calcsize(fmt)))
                strtab_offset = fields[4]  # sh_offset
                strtab_size = fields[5]    # sh_size
            else:
                fmt = f"{self._endian}IIIIIIIIII"
                fields = struct.unpack(fmt, self._file.read(struct.calcsize(fmt)))
                strtab_offset = fields[4]  # sh_offset
                strtab_size = fields[5]    # sh_size
            
            # Read string table
            self._file.seek(strtab_offset)
            strtab_data = self._file.read(strtab_size)
            
            # Create string table lookup
            self.string_table = self._create_string_table(strtab_data)
            
            # Restore position
            self._file.seek(current_pos)
        
        # Now read all section headers
        for i in range(shnum):
            offset = shoff + i * shentsize
            self._file.seek(offset)
            
            if is_64bit:
                fmt = f"{self._endian}IIQQQQIIQQ"
                fields = struct.unpack(fmt, self._file.read(struct.calcsize(fmt)))
                section = {
                    "name_index": fields[0],
                    "name": self._get_string(fields[0]),
                    "type": fields[1],
                    "flags": fields[2],
                    "addr": fields[3],
                    "offset": fields[4],
                    "size": fields[5],
                    "link": fields[6],
                    "info": fields[7],
                    "addralign": fields[8],
                    "entsize": fields[9],
                }
            else:
                fmt = f"{self._endian}IIIIIIIIII"
                fields = struct.unpack(fmt, self._file.read(struct.calcsize(fmt)))
                section = {
                    "name_index": fields[0],
                    "name": self._get_string(fields[0]),
                    "type": fields[1],
                    "flags": fields[2],
                    "addr": fields[3],
                    "offset": fields[4],
                    "size": fields[5],
                    "link": fields[6],
                    "info": fields[7],
                    "addralign": fields[8],
                    "entsize": fields[9],
                }
                
            self.section_headers.append(section)
    
    def _parse_program_headers(self):
        """Parse program headers"""
        is_64bit = self.elf_header["is_64bit"]
        phoff = self.elf_header["phoff"]
        phentsize = self.elf_header["phentsize"]
        phnum = self.elf_header["phnum"]
        
        self.program_headers = []
        
        for i in range(phnum):
            offset = phoff + i * phentsize
            self._file.seek(offset)
            
            if is_64bit:
                fmt = f"{self._endian}IIQQQQQQ"
                fields = struct.unpack(fmt, self._file.read(struct.calcsize(fmt)))
                segment = {
                    "type": fields[0],
                    "flags": fields[1],
                    "offset": fields[2],
                    "vaddr": fields[3],
                    "paddr": fields[4],
                    "filesz": fields[5],
                    "memsz": fields[6],
                    "align": fields[7],
                }
            else:
                fmt = f"{self._endian}IIIIIIII"
                fields = struct.unpack(fmt, self._file.read(struct.calcsize(fmt)))
                segment = {
                    "type": fields[0],
                    "offset": fields[1],
                    "vaddr": fields[2],
                    "paddr": fields[3],
                    "filesz": fields[4],
                    "memsz": fields[5],
                    "flags": fields[6],
                    "align": fields[7],
                }
                
            self.program_headers.append(segment)
    
    def _parse_symbols(self):
        """Parse symbol tables"""
        self.symbols = []
        self.dynamic_symbols = []
        
        # Find symbol table sections
        symtab_section = None
        dynsym_section = None
        strtab_section = None
        dynstr_section = None
        
        for section in self.section_headers:
            if section["type"] == ElfSectionType.SHT_SYMTAB:
                symtab_section = section
            elif section["type"] == ElfSectionType.SHT_DYNSYM:
                dynsym_section = section
            elif section["name"] == ".strtab":
                strtab_section = section
            elif section["name"] == ".dynstr":
                dynstr_section = section
        
        # Parse symbol table if found
        if symtab_section and strtab_section:
            self.symbols = self._parse_symbol_table(
                symtab_section["offset"],
                symtab_section["size"],
                symtab_section["entsize"],
                strtab_section["offset"],
                strtab_section["size"]
            )
            
        # Parse dynamic symbol table if found
        if dynsym_section and dynstr_section:
            self.dynamic_symbols = self._parse_symbol_table(
                dynsym_section["offset"],
                dynsym_section["size"],
                dynsym_section["entsize"],
                dynstr_section["offset"],
                dynstr_section["size"]
            )
    
    def _parse_symbol_table(self, offset: int, size: int, entsize: int, 
                           strtab_offset: int, strtab_size: int) -> List[Dict[str, Any]]:
        """Parse a symbol table
        
        Args:
            offset: Offset of symbol table
            size: Size of symbol table
            entsize: Size of each entry
            strtab_offset: Offset of string table
            strtab_size: Size of string table
            
        Returns:
            List of symbol dictionaries
        """
        symbols = []
        is_64bit = self.elf_header["is_64bit"]
        
        # Read string table data
        self._file.seek(strtab_offset)
        strtab_data = self._file.read(strtab_size)
        strtab = self._create_string_table(strtab_data)
        
        # Read symbol table entries
        num_entries = size // entsize
        for i in range(num_entries):
            entry_offset = offset + i * entsize
            self._file.seek(entry_offset)
            
            if is_64bit:
                fmt = f"{self._endian}IBBHQQ"
                fields = struct.unpack(fmt, self._file.read(struct.calcsize(fmt)))
                symbol = {
                    "name_index": fields[0],
                    "name": self._get_string_from_table(fields[0], strtab),
                    "info": fields[1],
                    "other": fields[2],
                    "shndx": fields[3],
                    "value": fields[4],
                    "size": fields[5],
                    "bind": fields[1] >> 4,
                    "type": fields[1] & 0xf,
                }
            else:
                fmt = f"{self._endian}IIIBBH"
                fields = struct.unpack(fmt, self._file.read(struct.calcsize(fmt)))
                symbol = {
                    "name_index": fields[0],
                    "name": self._get_string_from_table(fields[0], strtab),
                    "value": fields[1],
                    "size": fields[2],
                    "info": fields[3],
                    "other": fields[4],
                    "shndx": fields[5],
                    "bind": fields[3] >> 4,
                    "type": fields[3] & 0xf,
                }
                
            symbols.append(symbol)
            
        return symbols
    
    def _create_string_table(self, data: bytes) -> Dict[int, str]:
        """Create a string table lookup from raw data
        
        Args:
            data: Raw string table data
            
        Returns:
            Dictionary mapping indices to strings
        """
        table = {}
        i = 0
        
        while i < len(data):
            if data[i] == 0:
                i += 1
                continue
                
            # Start of a string
            start = i
            while i < len(data) and data[i] != 0:
                i += 1
                
            # Extract the string
            try:
                string = data[start:i].decode('utf-8')
                table[start] = string
            except UnicodeDecodeError:
                # Handle non-UTF-8 strings
                table[start] = data[start:i].decode('latin-1')
                
            i += 1
            
        return table
    
    def _get_string(self, index: int) -> str:
        """Get a string from the section name string table
        
        Args:
            index: Index into the string table
            
        Returns:
            String value or empty string if not found
        """
        return self.string_table.get(index, "")
    
    def _get_string_from_table(self, index: int, string_table: Dict[int, str]) -> str:
        """Get a string from the specified string table
        
        Args:
            index: Index into the string table
            string_table: String table dictionary
            
        Returns:
            String value or empty string if not found
        """
        return string_table.get(index, "")
    
    def find_section_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        """Find a section by name
        
        Args:
            name: Section name to find
            
        Returns:
            Section dictionary or None if not found
        """
        for section in self.section_headers:
            if section["name"] == name:
                return section
        return None
    
    def find_segment_by_type(self, segment_type: int) -> Optional[Dict[str, Any]]:
        """Find a segment by type
        
        Args:
            segment_type: Segment type to find (from ElfSegmentType)
            
        Returns:
            Segment dictionary or None if not found
        """
        for segment in self.program_headers:
            if segment["type"] == segment_type:
                return segment
        return None
    
    def get_segment_data(self, segment: Dict[str, Any]) -> bytes:
        """Get the raw data for a program segment
        
        Args:
            segment: Segment dictionary
            
        Returns:
            Raw segment data
        """
        self._file.seek(segment["offset"])
        return self._file.read(segment["filesz"])
    
    def get_section_data(self, section: Dict[str, Any]) -> bytes:
        """Get the raw data for a section
        
        Args:
            section: Section dictionary
            
        Returns:
            Raw section data
        """
        if section["type"] == ElfSectionType.SHT_NOBITS:
            # Section has no data in the file (like .bss)
            return b''
            
        self._file.seek(section["offset"])
        return self._file.read(section["size"])
    
    def close(self):
        """Close the file if open"""
        if self._file and not isinstance(self._file, bytes) and hasattr(self._file, 'close'):
            self._file.close()
            self._file = None
