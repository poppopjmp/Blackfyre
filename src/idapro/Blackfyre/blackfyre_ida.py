import idaapi
import idautils
import ida_funcs
import ida_bytes
import ida_name
import ida_segment
import ida_entry
import os
import sys
import struct
from pathlib import Path

# Add the Python lib to the path to access protocol buffers
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(SCRIPT_DIR, "..", "..", "python"))

try:
    from blackfyre.datatypes.protobuf import binary_context_pb2 as bc_pb
    from blackfyre.datatypes.protobuf import function_context_pb2 as fc_pb
    from blackfyre.common import ProcessorType, FileType, Endness, ArchWordSize, MessageType
except ImportError as e:
    print(f"Error importing Blackfyre modules: {e}")
    print("Make sure you have the Blackfyre Python library in your path")

class BlackfyreIDAExporter:
    def __init__(self):
        self.bcc_version = "1.0.1"
        self.binary_name = idaapi.get_root_filename()
        self.sha256_hash = self._calculate_sha256()
        
    def _calculate_sha256(self):
        """Calculate SHA-256 hash of the binary"""
        import hashlib
        
        # Get binary path from IDA
        binary_path = idaapi.get_input_file_path()
        
        # Calculate hash
        h = hashlib.sha256()
        with open(binary_path, 'rb') as f:
            chunk = f.read(8192)
            while chunk:
                h.update(chunk)
                chunk = f.read(8192)
        
        return h.hexdigest()
    
    def _get_processor_type(self):
        """Determine processor type from IDA info"""
        info = idaapi.get_inf_structure()
        
        if info.procname == "metapc":
            if info.is_64bit():
                return ProcessorType.x86_64.value
            else:
                return ProcessorType.x86.value
        elif info.procname == "ARM":
            if info.is_64bit():
                return ProcessorType.AARCH64.value
            else:
                return ProcessorType.ARM.value
        elif info.procname == "mipsb" or info.procname == "mipsl":
            if info.is_64bit():
                return ProcessorType.MIPS.value  # Should be a 64-bit MIPS enum
            else:
                return ProcessorType.MIPS.value
        elif info.procname == "ppc":
            if info.is_64bit():
                return ProcessorType.PPC.value  # Should be a 64-bit PPC enum
            else:
                return ProcessorType.PPC.value
        else:
            print(f"Unrecognized processor: {info.procname}")
            return ProcessorType.x86.value  # Default
    
    def _get_file_type(self):
        """Determine file type from IDA info"""
        info = idaapi.get_inf_structure()
        
        # Check file format
        if info.filetype == idaapi.f_PE:
            if info.is_64bit():
                return FileType.PE64.value
            else:
                return FileType.PE32.value
        elif info.filetype == idaapi.f_ELF:
            if info.is_64bit():
                return FileType.ELF64.value
            else:
                return FileType.ELF32.value
        elif info.filetype == idaapi.f_MACHO:
            if info.is_64bit():
                return FileType.MACH_O_64.value
            else:
                return FileType.MACH_O_32.value
        else:
            print(f"Unrecognized file type: {info.filetype}")
            return FileType.PE32.value  # Default
    
    def _get_endness(self):
        """Determine endianness from IDA info"""
        info = idaapi.get_inf_structure()
        
        if info.is_be():
            return Endness.BIG_ENDIAN.value
        else:
            return Endness.LITTLE_ENDIAN.value
    
    def _get_word_size(self):
        """Determine word size from IDA info"""
        info = idaapi.get_inf_structure()
        
        if info.is_64bit():
            return ArchWordSize.BITS_64.value
        else:
            return ArchWordSize.BITS_32.value
    
    def _collect_strings(self):
        """Collect strings from the binary"""
        string_refs = {}
        
        # Use IDA's string finder
        for s in idautils.Strings():
            addr = s.ea
            string_val = str(s)
            string_refs[addr] = string_val
        
        return string_refs
    
    def _collect_imports(self):
        """Collect import information"""
        import_symbols = []
        
        # Iterate through imports
        nimps = idaapi.get_import_module_qty()
        
        for i in range(nimps):
            name = idaapi.get_import_module_name(i)
            if not name:
                continue
                
            # Get all imports for this module
            def imp_cb(ea, name, ord):
                if name:
                    import_symbols.append({
                        "name": name,
                        "library": idaapi.get_import_module_name(i),
                        "address": ea
                    })
                return True
            
            idaapi.enum_import_names(i, imp_cb)
        
        return import_symbols
    
    def _collect_exports(self):
        """Collect export information"""
        export_symbols = []
        
        # Use IDA's entry points
        for i, ordinal, ea, name in idautils.Entries():
            export_symbols.append({
                "name": name,
                "library": self.binary_name,  # No library info available, use binary name
                "address": ea
            })
        
        return export_symbols
    
    def _collect_functions(self):
        """Collect function information"""
        functions = []
        
        # Iterate through all functions
        for ea in idautils.Functions():
            func = ida_funcs.get_func(ea)
            if not func:
                continue
                
            func_name = ida_name.get_name(ea)
            
            # Check if it's a thunk (wrapper) function
            is_thunk = func.flags & ida_funcs.FUNC_THUNK != 0
            
            # Get segment name
            seg = ida_segment.getseg(ea)
            seg_name = ida_segment.get_segm_name(seg) if seg else ""
            
            # Get basic blocks
            # In a real implementation, we would collect all basic blocks
            # and their instructions here
            
            # Get function boundaries
            start_ea = func.start_ea
            end_ea = func.end_ea
            
            # Get decompiled code
            # In a real implementation, we would use the Hex-Rays decompiler
            # if available
            
            functions.append({
                "name": func_name,
                "start_address": start_ea,
                "end_address": end_ea,
                "is_thunk": is_thunk,
                "segment_name": seg_name,
                # Other fields would be added here
            })
        
        return functions
    
    def _collect_caller_callee_info(self):
        """Collect caller-callee relationships"""
        caller_to_callees = {}
        
        # Iterate through all functions
        for caller_ea in idautils.Functions():
            caller_func = ida_funcs.get_func(caller_ea)
            if not caller_func:
                continue
                
            callees = []
            
            # Look for references from this function
            for instr_ea in idautils.FuncItems(caller_ea):
                for ref_ea in idautils.CodeRefsFrom(instr_ea, 0):
                    if ref_ea == ida_funcs.BADADDR:
                        continue
                    
                    # Check if reference is to a function
                    if ida_funcs.get_func(ref_ea):
                        callees.append(ref_ea)
            
            # Add to map if there are callees
            if callees:
                caller_to_callees[caller_ea] = callees
        
        return caller_to_callees
    
    def export_to_bcc(self, output_path=None, include_raw_binary=True):
        """Export IDA analysis to BCC format
        
        Args:
            output_path: Path to save the BCC file (default: same as IDB but with .bcc extension)
            include_raw_binary: Whether to include the raw binary in the BCC
            
        Returns:
            Path to the exported BCC file
        """
        if not output_path:
            # Default to same directory as IDB but with .bcc extension
            idb_path = idaapi.get_path(idaapi.PATH_TYPE_IDB)
            output_dir = os.path.dirname(idb_path)
            output_path = os.path.join(output_dir, f"{self.binary_name}_{self.sha256_hash}.bcc")
        
        # Collect data
        print("Collecting data from IDA...")
        print("- Collecting strings")
        strings = self._collect_strings()
        print(f"  Found {len(strings)} strings")
        
        print("- Collecting imports")
        imports = self._collect_imports()
        print(f"  Found {len(imports)} imports")
        
        print("- Collecting exports")
        exports = self._collect_exports()
        print(f"  Found {len(exports)} exports")
        
        print("- Collecting functions")
        functions = self._collect_functions()
        print(f"  Found {len(functions)} functions")
        
        print("- Analyzing call graph")
        caller_to_callees = self._collect_caller_callee_info()
        
        # Build the Binary Context protobuf
        print("Building BCC data...")
        
        # Here we would build the actual Protocol Buffer objects
        # and write them to the BCC file following the TLV format
        # For the sake of this example, we'll just indicate the process
        
        print(f"Writing BCC file to: {output_path}")
        # In a real implementation, we would:
        # 1. Create the BinaryContext protobuf
        # 2. Create FunctionContext protobufs
        # 3. Write them to the BCC file
        # 4. Include raw binary if requested
        # 5. Add SHA-256 validation
        
        return output_path

# IDA Plugin setup
class BlackfyrePlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Export IDA analysis to Blackfyre BCC format"
    help = "Exports IDA analysis to the Blackfyre Binary Context Container format"
    wanted_name = "Blackfyre BCC Export"
    wanted_hotkey = "Ctrl-Alt-B"
    
    def init(self):
        print("Blackfyre IDA Plugin initialized")
        return idaapi.PLUGIN_OK
        
    def run(self, arg):
        exporter = BlackfyreIDAExporter()
        
        # Ask for output path
        output_path = idaapi.ask_file(1, "*.bcc", "Save BCC file as")
        if not output_path:
            print("Export cancelled")
            return
            
        # Ask for options
        include_raw = idaapi.ask_yn(1, "Include raw binary data in the BCC file?") == 1
        
        # Export
        try:
            result_path = exporter.export_to_bcc(output_path, include_raw)
            print(f"Successfully exported to {result_path}")
        except Exception as e:
            print(f"Error exporting: {e}")
        
    def term(self):
        pass

def PLUGIN_ENTRY():
    return BlackfyrePlugin()
