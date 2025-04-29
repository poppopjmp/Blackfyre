import os
import sys
import hashlib
from pathlib import Path
from binaryninja import BinaryView, BinaryReader, SaveFileNameField, get_save_filename_input

# Add the Python lib to the path to access protocol buffers
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(SCRIPT_DIR, "..", "..", "python"))

try:
    from blackfyre.common import ProcessorType, FileType, Endness, ArchWordSize, MessageType
except ImportError as e:
    print(f"Error importing Blackfyre modules: {e}")
    print("Make sure you have the Blackfyre Python library in your path")

class BlackfyreBinaryNinjaExporter:
    def __init__(self, bv):
        """Initialize the exporter
        
        Args:
            bv: Binary Ninja BinaryView object
        """
        self.bv = bv
        self.binary_name = os.path.basename(bv.file.filename)
        self.sha256_hash = self._calculate_sha256()
        
    def _calculate_sha256(self):
        """Calculate SHA-256 hash of the binary"""
        # Open the file directly to calculate hash
        try:
            with open(self.bv.file.filename, 'rb') as f:
                h = hashlib.sha256()
                chunk = f.read(8192)
                while chunk:
                    h.update(chunk)
                    chunk = f.read(8192)
                return h.hexdigest()
        except:
            # Fallback to reading from Binary Ninja's view
            h = hashlib.sha256()
            for segment in self.bv.segments:
                data = self.bv.read(segment.start, segment.length)
                h.update(data)
            return h.hexdigest()
    
    def _get_processor_type(self):
        """Determine processor type from Binary Ninja info"""
        arch = self.bv.arch.name.lower()
        
        if "x86" in arch:
            if "64" in arch:
                return ProcessorType.x86_64.value
            else:
                return ProcessorType.x86.value
        elif "arm" in arch:
            if "64" in arch or "aarch64" in arch:
                return ProcessorType.AARCH64.value
            else:
                return ProcessorType.ARM.value
        elif "mips" in arch:
            return ProcessorType.MIPS.value
        elif "ppc" in arch:
            return ProcessorType.PPC.value
        else:
            print(f"Unrecognized architecture: {arch}")
            return ProcessorType.x86.value  # Default
    
    def _get_file_type(self):
        """Determine file type"""
        platform = self.bv.platform.name.lower()
        
        if "pe" in platform or "windows" in platform:
            if self.bv.arch.address_size == 8:
                return FileType.PE64.value
            else:
                return FileType.PE32.value
        elif "elf" in platform or "linux" in platform:
            if self.bv.arch.address_size == 8:
                return FileType.ELF64.value
            else:
                return FileType.ELF32.value
        elif "mac" in platform:
            if self.bv.arch.address_size == 8:
                return FileType.MACH_O_64.value
            else:
                return FileType.MACH_O_32.value
        else:
            print(f"Unrecognized platform: {platform}")
            if self.bv.arch.address_size == 8:
                return FileType.PE64.value
            else:
                return FileType.PE32.value
    
    def _get_endness(self):
        """Determine endianness"""
        return Endness.BIG_ENDIAN.value if self.bv.arch.endianness else Endness.LITTLE_ENDIAN.value
    
    def _get_word_size(self):
        """Determine word size"""
        if self.bv.arch.address_size == 8:
            return ArchWordSize.BITS_64.value
        elif self.bv.arch.address_size == 4:
            return ArchWordSize.BITS_32.value
        elif self.bv.arch.address_size == 2:
            return ArchWordSize.BITS_16.value
        else:
            print(f"Unusual address size: {self.bv.arch.address_size}")
            return ArchWordSize.BITS_32.value  # Default
            
    def _collect_strings(self):
        """Collect strings from the binary"""
        string_refs = {}
        
        for string in self.bv.strings:
            string_refs[string.start] = string.value
            
        return string_refs
    
    def _collect_imports(self):
        """Collect import information"""
        import_symbols = []
        
        for sym in self.bv.get_symbols():
            if sym.type == 'ImportedFunctionSymbol':
                import_symbols.append({
                    "name": sym.name,
                    "library": sym.namespace, 
                    "address": sym.address
                })
                
        return import_symbols
        
    def _collect_exports(self):
        """Collect export information"""
        export_symbols = []
        
        for sym in self.bv.get_symbols():
            if sym.type == 'ExportedFunctionSymbol':
                export_symbols.append({
                    "name": sym.name,
                    "library": self.binary_name,  # Default to binary name
                    "address": sym.address
                })
                
        return export_symbols
    
    def _collect_functions(self):
        """Collect function information"""
        functions = []
        
        for func in self.bv.functions:
            # Basic function info
            func_info = {
                "name": func.name,
                "start_address": func.start,
                "end_address": func.highest_address,
                "is_thunk": len(list(func.basic_blocks)) <= 1 and func.symbol.type == 'ImportedFunctionSymbol',
                "segment_name": self._get_segment_name(func.start),
                # In a real implementation, we would collect basic block and instruction data here
            }
            
            functions.append(func_info)
            
        return functions
    
    def _get_segment_name(self, address):
        """Get the segment name for an address"""
        for segment in self.bv.segments:
            if segment.start <= address < segment.end:
                return segment.name
        return ""
    
    def _collect_caller_callee_info(self):
        """Collect caller-callee relationships"""
        caller_to_callees = {}
        
        for func in self.bv.functions:
            callees = []
            
            # Get all call sites in the function
            for block in func.basic_blocks:
                for edge in block.outgoing_edges:
                    if edge.type == 'CallDestination':
                        # Get the target function
                        target = edge.target.function
                        if target:
                            callees.append(target.start)
            
            if callees:
                caller_to_callees[func.start] = callees
                
        return caller_to_callees
    
    def export_to_bcc(self):
        """Export Binary Ninja analysis to BCC format"""
        # Ask for output location
        output_field = SaveFileNameField("Save BCC file")
        input_result = get_save_filename_input("Export to Blackfyre BCC", "Export", output_field)
        
        if input_result is None:
            print("Export cancelled")
            return
            
        output_path = output_field.result
        
        # In a real implementation, we would collect all data and build the 
        # Protocol Buffer messages here, following the same format as the Ghidra plugin
        
        print(f"Exporting to {output_path}...")
        print(f"Binary name: {self.binary_name}")
        print(f"SHA-256: {self.sha256_hash}")
        
        # Collect data
        strings = self._collect_strings()
        imports = self._collect_imports()
        exports = self._collect_exports()
        functions = self._collect_functions()
        caller_to_callees = self._collect_caller_callee_info()
        
        print(f"Found {len(strings)} strings")
        print(f"Found {len(imports)} imports")
        print(f"Found {len(exports)} exports")
        print(f"Found {len(functions)} functions")
        
        # Since this is a skeleton implementation, we'll print a success message
        # without actually writing a file
        print(f"Export to {output_path} completed (simulated)")
        print("Note: This is a skeleton implementation. Full implementation would build and write the BCC file")
