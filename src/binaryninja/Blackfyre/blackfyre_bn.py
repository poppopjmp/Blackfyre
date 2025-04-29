import binaryninja
import hashlib
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

class BlackfyreBinaryNinjaExporter:
    def __init__(self, binary_view):
        self.bv = binary_view
        self.bcc_version = "1.0.1"
        self.binary_name = os.path.basename(self.bv.file.original_filename)
        self.sha256_hash = self._calculate_sha256()
        
    def _calculate_sha256(self):
        """Calculate SHA-256 hash of the binary"""
        binary_path = self.bv.file.original_filename
        
        # Calculate hash
        h = hashlib.sha256()
        with open(binary_path, 'rb') as f:
            chunk = f.read(8192)
            while chunk:
                h.update(chunk)
                chunk = f.read(8192)
        
        return h.hexdigest()
    
    def _get_processor_type(self):
        """Determine processor type from Binary Ninja"""
        arch = self.bv.arch.name.lower()
        
        if "x86_64" in arch:
            return ProcessorType.x86_64.value
        elif "x86" in arch:
            return ProcessorType.x86.value
        elif "aarch64" in arch:
            return ProcessorType.AARCH64.value
        elif "arm" in arch:
            return ProcessorType.ARM.value
        elif "mips" in arch:
            return ProcessorType.MIPS.value
        elif "ppc" in arch:
            return ProcessorType.PPC.value
        else:
            print(f"Unrecognized processor: {arch}")
            return ProcessorType.x86.value  # Default
    
    def _get_file_type(self):
        """Determine file type from Binary Ninja"""
        platform = self.bv.platform.name.lower()
        
        if "pe" in platform:
            if self.bv.arch.address_size == 8:
                return FileType.PE64.value
            else:
                return FileType.PE32.value
        elif "elf" in platform:
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
            print(f"Unrecognized file type platform: {platform}")
            return FileType.PE32.value  # Default
    
    def _get_endness(self):
        """Determine endianness from Binary Ninja"""
        if self.bv.arch.endianness == binaryninja.Endianness.BigEndian:
            return Endness.BIG_ENDIAN.value
        else:
            return Endness.LITTLE_ENDIAN.value
    
    def _get_word_size(self):
        """Determine word size from Binary Ninja"""
        if self.bv.arch.address_size == 8:
            return ArchWordSize.BITS_64.value
        else:
            return ArchWordSize.BITS_32.value
    
    def _collect_strings(self):
        """Collect strings from the binary"""
        string_refs = {}
        
        # Get strings discovered by Binary Ninja
        for string in self.bv.get_strings():
            string_refs[string.start] = string.value
        
        return string_refs
    
    def _collect_imports(self):
        """Collect import information"""
        import_symbols = []
        
        # Get imports from Binary Ninja
        for sym in self.bv.get_symbols():
            if sym.type == binaryninja.SymbolType.ImportedFunctionSymbol or sym.type == binaryninja.SymbolType.ImportedDataSymbol:
                # Get the library name from import - this might need adjustment based on Binary Ninja's API
                library = "unknown"
                for import_addr in self.bv.get_import_addresses():
                    if import_addr == sym.address:
                        library = self.bv.get_symbol_at(import_addr).namespace
                        break
                
                import_symbols.append({
                    "name": sym.name,
                    "library": library,
                    "address": sym.address
                })
        
        return import_symbols
    
    def _collect_exports(self):
        """Collect export information"""
        export_symbols = []
        
        # Get exports from Binary Ninja
        for sym in self.bv.get_symbols():
            if sym.type == binaryninja.SymbolType.ExportedFunctionSymbol or sym.type == binaryninja.SymbolType.ExportedDataSymbol:
                export_symbols.append({
                    "name": sym.name,
                    "library": self.binary_name,
                    "address": sym.address
                })
        
        return export_symbols
    
    def _collect_functions(self):
        """Collect function information"""
        functions = []
        
        # Get functions from Binary Ninja
        for func in self.bv.functions:
            # Get segment name
            segment = self.bv.get_segment_at(func.start)
            seg_name = segment.name if segment else ""
            
            # Check if it's a thunk
            is_thunk = func.is_thunk
            
            functions.append({
                "name": func.name,
                "start_address": func.start,
                "end_address": func.start + func.total_bytes,
                "is_thunk": is_thunk,
                "segment_name": seg_name,
            })
        
        return functions
    
    def _collect_caller_callee_info(self):
        """Collect caller-callee relationships"""
        caller_to_callees = {}
        
        # Get caller-callee relationships from Binary Ninja
        for caller in self.bv.functions:
            callees = []
            
            # Get direct calls from the caller
            for ref in caller.call_sites:
                callee_addr = ref.addr
                if self.bv.get_function_at(callee_addr):
                    callees.append(callee_addr)
            
            if callees:
                caller_to_callees[caller.start] = callees
        
        return caller_to_callees
    
    def _collect_basic_blocks(self, func):
        """Collect basic block information for a function"""
        blocks = []
        
        for block in func.basic_blocks:
            # Get incoming and outgoing edges
            incoming_edges = [edge.source.start for edge in block.incoming_edges]
            outgoing_edges = [edge.target.start for edge in block.outgoing_edges]
            
            # Enhanced instruction collection with operand analysis
            instructions = []
            for insn in block:  # Iterate through instructions directly for better analysis
                # Get basic instruction info
                address = insn.address
                disasm = insn.get_disassembly_text()
                mnemonic = insn.operation.name
                
                # Analyze operands
                operands = []
                for operand in insn.operands:
                    op_type = str(operand.type)
                    op_value = None
                    op_is_address = False
                    
                    # Extract operand value based on type
                    if operand.type == binaryninja.operandtype.PossibleAddressToken:
                        op_value = operand.value
                        op_is_address = True
                    elif operand.type == binaryninja.operandtype.IntegerToken:
                        op_value = operand.value
                    elif hasattr(operand, 'value'):
                        op_value = operand.value
                    
                    # Check for string references
                    if op_is_address and op_value is not None:
                        for string in self.bv.get_strings():
                            if string.start == op_value:
                                op_string = string.value
                                operands.append({
                                    "type": op_type,
                                    "value": op_value,
                                    "is_address": op_is_address,
                                    "string_value": op_string
                                })
                                continue
                    
                    operands.append({
                        "type": op_type,
                        "value": op_value,
                        "is_address": op_is_address
                    })
                
                # Get any data references from this instruction
                data_refs = [ref.address for ref in self.bv.get_data_refs_from(address)]
                code_refs = [ref.address for ref in self.bv.get_code_refs_from(address)]
                
                instructions.append({
                    "address": address,
                    "disassembly": str(disasm),
                    "mnemonic": mnemonic,
                    "operands": operands,
                    "data_refs": data_refs,
                    "code_refs": code_refs
                })
            
            blocks.append({
                "start_address": block.start,
                "end_address": block.end,
                "incoming_edges": incoming_edges,
                "outgoing_edges": outgoing_edges,
                "instructions": instructions,
                "has_call": any(insn.operation == binaryninja.lowlevelil.LowLevelILOperation.LLIL_CALL for insn in block.low_level_il_instructions)
            })
        
        return blocks
    
    def _collect_function_cross_references(self, func_addr):
        """Collect cross-references to a function"""
        xrefs = []
        
        # Get references to this function
        for ref in self.bv.get_code_refs(func_addr):
            # Get additional context about the reference
            ref_func = ref.function
            ref_address = ref.address
            instr = None
            
            if ref_func:
                # Try to get the instruction at this reference
                instr = self.bv.get_disassembly(ref_address)
            
            xrefs.append({
                "address": ref_address,
                "function": ref_func.name if ref_func else "unknown",
                "instruction": instr,
                "is_call": self.bv.is_call_instruction(ref_address)
            })
        
        return xrefs
    
    def _get_decompiled_code(self, func):
        """Get decompiled code if available through Binary Ninja's API"""
        try:
            # Check if decompilation is available
            if hasattr(func, 'hlil') and func.hlil:
                return str(func.hlil)
        except:
            pass
        return None
    
    def _collect_data_variables(self):
        """Collect data variables and their references"""
        data_vars = []
        
        for var in self.bv.data_vars:
            # Get type information
            var_type = str(self.bv.get_type_at(var))
            
            # Get value if readable
            value = None
            if self.bv.is_valid_offset(var):
                size = self.bv.get_type_at(var).width if self.bv.get_type_at(var) else 1
                if size > 0 and size <= 8:  # Reasonable size for direct value
                    try:
                        value = self.bv.read(var, size).hex()
                    except:
                        pass
            
            # Get cross-references
            xrefs = []
            for ref in self.bv.get_code_refs(var):
                xrefs.append(ref.address)
            
            data_vars.append({
                "address": var,
                "name": self.bv.get_symbol_at(var).name if self.bv.get_symbol_at(var) else "",
                "type": var_type,
                "value": value,
                "xrefs": xrefs
            })
        
        return data_vars
    
    def _collect_sections(self):
        """Collect section information"""
        sections = []
        
        for segment in self.bv.segments:
            sections.append({
                "name": segment.name,
                "start_address": segment.start,
                "end_address": segment.end,
                "readable": segment.readable,
                "writable": segment.writable,
                "executable": segment.executable
            })
        
        return sections
    
    def _collect_extended_function_info(self, functions, caller_to_callees):
        """Collect extended information for functions"""
        extended_functions = []
        
        for func_info in functions:
            func = self.bv.get_function_at(func_info["start_address"])
            if not func:
                extended_functions.append(func_info)
                continue
                
            # Get basic blocks
            basic_blocks = self._collect_basic_blocks(func)
            
            # Get cross-references to this function
            xrefs = self._collect_function_cross_references(func.start)
            
            # Get decompiled code if available
            decompiled = self._get_decompiled_code(func)
            
            # Add analysis flags and metadata
            analysis_info = {
                "is_library": func.is_library_function,
                "has_unresolved_calls": any(callee == 0 for callee in caller_to_callees.get(func.start, [])),
                "is_imported": func.symbol.type == binaryninja.SymbolType.ImportedFunctionSymbol if func.symbol else False,
                "is_exported": func.symbol.type == binaryninja.SymbolType.ExportedFunctionSymbol if func.symbol else False,
                "stack_frame_size": func.stack_adjustment.value if hasattr(func, 'stack_adjustment') else 0,
                "has_loops": any(len(block.incoming_edges) > 1 for block in func.basic_blocks),
                "call_convention": str(func.calling_convention) if func.calling_convention else "unknown"
            }
            
            # Combine with original function info
            extended_func = {
                **func_info,
                "basic_blocks": basic_blocks,
                "xrefs": xrefs,
                "decompiled": decompiled,
                "analysis": analysis_info
            }
            
            extended_functions.append(extended_func)
        
        return extended_functions
    
    def export_to_bcc(self, output_path=None, include_raw_binary=True, extended_analysis=True):
        """Export Binary Ninja analysis to BCC format
        
        Args:
            output_path: Path to save the BCC file (default: same directory as binary with .bcc extension)
            include_raw_binary: Whether to include the raw binary in the BCC
            extended_analysis: Whether to include extended analysis data
            
        Returns:
            Path to the exported BCC file
        """
        if not output_path:
            # Default to same directory as binary but with .bcc extension
            binary_dir = os.path.dirname(self.bv.file.original_filename)
            output_path = os.path.join(binary_dir, f"{self.binary_name}_{self.sha256_hash}.bcc")
        
        # Collect data
        print("Collecting data from Binary Ninja...")
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
        
        # Collect additional data if extended analysis is enabled
        if extended_analysis:
            print("- Collecting sections")
            sections = self._collect_sections()
            print(f"  Found {len(sections)} sections")
            
            print("- Collecting data variables")
            data_vars = self._collect_data_variables()
            print(f"  Found {len(data_vars)} data variables")
            
            print("- Performing extended function analysis")
            functions = self._collect_extended_function_info(functions, caller_to_callees)
        
        # Build the Binary Context protobuf
        print("Building BCC data...")
        
        # Create the BinaryContext protobuf
        binary_context = bc_pb.BinaryContext()
        binary_context.metadata.bcc_version = self.bcc_version
        binary_context.metadata.binary_name = self.binary_name
        binary_context.metadata.sha256 = self.sha256_hash
        binary_context.metadata.processor_type = self._get_processor_type()
        binary_context.metadata.file_type = self._get_file_type()
        binary_context.metadata.endness = self._get_endness()
        binary_context.metadata.word_size = self._get_word_size()
        binary_context.metadata.tool_name = "Binary Ninja"
        binary_context.metadata.tool_version = binaryninja.core_version

        # Add additional metadata if available
        if hasattr(self.bv, 'entry_point'):
            binary_context.metadata.entry_point = self.bv.entry_point
        
        # Add strings
        for addr, string_val in strings.items():
            string_ref = binary_context.strings.add()
            string_ref.address = addr
            string_ref.value = string_val
        
        # Add imports
        for imp in imports:
            import_ref = binary_context.imports.add()
            import_ref.name = imp["name"]
            import_ref.library = imp["library"]
            import_ref.address = imp["address"]
        
        # Add exports
        for exp in exports:
            export_ref = binary_context.exports.add()
            export_ref.name = exp["name"]
            export_ref.address = exp["address"]
        
        # Add sections if extended analysis is enabled
        if extended_analysis and 'sections' in locals():
            for section in sections:
                section_ref = binary_context.sections.add()
                section_ref.name = section["name"]
                section_ref.start_address = section["start_address"]
                section_ref.end_address = section["end_address"]
                section_ref.permissions = (
                    (1 if section["readable"] else 0) |
                    (2 if section["writable"] else 0) |
                    (4 if section["executable"] else 0)
                )
        
        # Add functions
        for func in functions:
            # Create function context protobuf
            func_context = fc_pb.FunctionContext()
            func_context.name = func["name"]
            func_context.start_address = func["start_address"]
            func_context.end_address = func["end_address"]
            func_context.is_thunk = func["is_thunk"]
            func_context.segment_name = func["segment_name"]
            
            # Add callees if available
            if func["start_address"] in caller_to_callees:
                for callee in caller_to_callees[func["start_address"]]:
                    callee_ref = func_context.callees.add()
                    callee_ref.address = callee
                    callee_func = self.bv.get_function_at(callee)
                    if callee_func:
                        callee_ref.name = callee_func.name
            
            # Add extended analysis data if available
            if extended_analysis and "basic_blocks" in func:
                # Add basic blocks
                for block in func["basic_blocks"]:
                    bb = func_context.basic_blocks.add()
                    bb.start_address = block["start_address"]
                    bb.end_address = block["end_address"]
                    
                    # Add incoming/outgoing edges
                    for edge in block["incoming_edges"]:
                        bb.incoming_edges.append(edge)
                    for edge in block["outgoing_edges"]:
                        bb.outgoing_edges.append(edge)
                    
                    # Add instructions
                    for instr in block["instructions"]:
                        instruction = bb.instructions.add()
                        instruction.address = instr["address"]
                        instruction.disassembly = instr["disassembly"]
                
                # Add decompiled code if available
                if func.get("decompiled"):
                    func_context.decompiled_code = func["decompiled"]
                
                # Add analysis info if available
                if "analysis" in func:
                    for key, value in func["analysis"].items():
                        if isinstance(value, bool):
                            func_context.analysis_flags[key] = value
                        else:
                            func_context.analysis_metadata[key] = str(value)
            
            # Add function reference to binary context
            func_ref = binary_context.functions.add()
            func_ref.name = func["name"]
            func_ref.address = func["start_address"]
            func_ref.size = func["end_address"] - func["start_address"]
            
            # Serialize this function context
            func_bytes = func_context.SerializeToString()
        
        print(f"Writing BCC file to: {output_path}")
        
        # Write the BCC file - use same format as before for consistency
        with open(output_path, 'wb') as f:
            # Write TLV message for BinaryContext
            bc_bytes = binary_context.SerializeToString()
            f.write(struct.pack('!II', MessageType.BINARY_CONTEXT.value, len(bc_bytes)))
            f.write(bc_bytes)
            
            # Write function contexts
            for func in functions:
                func_context = fc_pb.FunctionContext()
                func_context.name = func["name"]
                func_context.start_address = func["start_address"]
                func_context.end_address = func["end_address"]
                func_context.is_thunk = func["is_thunk"]
                func_context.segment_name = func["segment_name"]
                
                # Add callees
                if func["start_address"] in caller_to_callees:
                    for callee in caller_to_callees[func["start_address"]]:
                        callee_ref = func_context.callees.add()
                        callee_ref.address = callee
                        callee_func = self.bv.get_function_at(callee)
                        if callee_func:
                            callee_ref.name = callee_func.name
                
                # Add extended analysis data if available
                if extended_analysis and "basic_blocks" in func:
                    # Add basic blocks
                    for block in func["basic_blocks"]:
                        bb = func_context.basic_blocks.add()
                        bb.start_address = block["start_address"]
                        bb.end_address = block["end_address"]
                        
                        # Add incoming/outgoing edges
                        for edge in block["incoming_edges"]:
                            bb.incoming_edges.append(edge)
                        for edge in block["outgoing_edges"]:
                            bb.outgoing_edges.append(edge)
                        
                        # Add instructions
                        for instr in block["instructions"]:
                            instruction = bb.instructions.add()
                            instruction.address = instr["address"]
                            instruction.disassembly = instr["disassembly"]
                    
                    # Add decompiled code if available
                    if func.get("decompiled"):
                        func_context.decompiled_code = func["decompiled"]
                
                # Serialize and write TLV
                func_bytes = func_context.SerializeToString()
                f.write(struct.pack('!II', MessageType.FUNCTION_CONTEXT.value, len(func_bytes)))
                f.write(func_bytes)
            
            # Include raw binary if requested
            if include_raw_binary:
                binary_path = self.bv.file.original_filename
                with open(binary_path, 'rb') as bin_file:
                    binary_data = bin_file.read()
                    f.write(struct.pack('!II', MessageType.RAW_BINARY.value, len(binary_data)))
                    f.write(binary_data)
            
            # Add SHA-256 validation at the end
            import hashlib
            hash_obj = hashlib.sha256()
            # Reset file pointer to beginning and hash all content
            f.flush()
            f.seek(0)
            content = f.read()
            hash_obj.update(content)
            f.write(struct.pack('!II', MessageType.SHA256_VALIDATION.value, 32))
            f.write(hash_obj.digest())
        
        return output_path

    def _apply_imported_data(self, binary_context, function_contexts):
        """Apply imported BCC data to the current binary view"""
        print("Applying imported BCC data...")
        
        # Track what's been applied
        applied_count = {
            "comments": 0,
            "function_names": 0,
            "types": 0,
            "tags": 0
        }
        
        # Apply binary-level information
        if binary_context:
            # Set binary tags
            self.bv.create_tag_type("BCC Import", "🔄")
            self.bv.create_tag(self.bv.tag_types["BCC Import"], 
                               f"Imported from {binary_context.metadata.binary_name}", True)
            
            # Import strings
            for string_ref in binary_context.strings:
                if self.bv.is_valid_offset(string_ref.address):
                    # Add a comment for the string
                    self.bv.set_comment_at(string_ref.address, f"String: {string_ref.value}")
                    applied_count["comments"] += 1
        
        # Apply function-level information
        for func_ctx in function_contexts:
            # Find matching function by address
            func = self.bv.get_function_at(func_ctx.start_address)
            if not func:
                continue
            
            # Apply function name if it's more specific (not like sub_XXXX)
            current_name = func.name
            imported_name = func_ctx.name
            if imported_name and not imported_name.startswith("sub_") and current_name.startswith("sub_"):
                func.name = imported_name
                applied_count["function_names"] += 1
            
            # Add function comment with source info
            func.comment = f"Imported from BCC - {func_ctx.name}"
            
            # Apply decompiled code as comment if available
            if func_ctx.decompiled_code:
                func.comment += f"\n\nDecompiled Code:\n{func_ctx.decompiled_code[:500]}..."
                applied_count["comments"] += 1
            
            # Apply basic block information
            for bb in func_ctx.basic_blocks:
                # Find matching block
                for block in func.basic_blocks:
                    if block.start == bb.start_address and block.end == bb.end_address:
                        # Apply block-level tags or comments
                        self.bv.set_comment_at(block.start, f"Block from {func_ctx.name}")
                        break
            
            # Create function tag
            func.create_tag(self.bv.tag_types["BCC Import"], "Imported Function", True)
            applied_count["tags"] += 1
                
        print(f"Applied data from BCC:")
        print(f"- {applied_count['comments']} comments")
        print(f"- {applied_count['function_names']} function names")
        print(f"- {applied_count['types']} types")
        print(f"- {applied_count['tags']} tags")
            
        return applied_count
    
    def _get_architecture_specific_info(self):
        """Get architecture-specific information"""
        arch_info = {}
        
        arch = self.bv.arch.name.lower()
        
        # x86/x86_64 specific
        if "x86" in arch:
            arch_info["instruction_set"] = "x86"
            arch_info["extensions"] = []
            
            # Check for extensions using platform features
            if hasattr(self.bv, "platform_features"):
                for feature in self.bv.platform_features:
                    if "sse" in feature.lower():
                        arch_info["extensions"].append("SSE")
                    if "avx" in feature.lower():
                        arch_info["extensions"].append("AVX")
        
        # ARM specific
        elif "arm" in arch:
            arch_info["instruction_set"] = "ARM"
            if "64" in arch or "aarch64" in arch:
                arch_info["extensions"] = ["AArch64"]
            else:
                # Check for Thumb mode
                arch_info["extensions"] = []
                if any(func.name.startswith(".thumb") for func in self.bv.functions):
                    arch_info["extensions"].append("Thumb")
        
        # MIPS specific
        elif "mips" in arch:
            arch_info["instruction_set"] = "MIPS"
            arch_info["extensions"] = []
            
        # PowerPC specific
        elif "ppc" in arch or "powerpc" in arch:
            arch_info["instruction_set"] = "PowerPC"
            arch_info["extensions"] = []
        
        return arch_info

    def import_bcc(self, input_path):
        """Import a BCC file and apply analysis to current binary
        
        Args:
            input_path: Path to the BCC file
            
        Returns:
            Dictionary with import results
        """
        print(f"Importing BCC file: {input_path}")
        
        try:
            # Read the BCC file
            with open(input_path, 'rb') as f:
                data = f.read()
            
            # Parse header
            offset = 0
            binary_context = None
            function_contexts = []
            
            while offset < len(data) - 8:  # Need at least 8 bytes for header
                # Parse TLV header
                msg_type, msg_len = struct.unpack('!II', data[offset:offset+8])
                offset += 8
                
                # Get message data
                if offset + msg_len > len(data):
                    print(f"Invalid message length at offset {offset-8}")
                    break
                
                msg_data = data[offset:offset+msg_len]
                offset += msg_len
                
                # Process message by type
                if msg_type == MessageType.BINARY_CONTEXT.value:
                    binary_context = bc_pb.BinaryContext()
                    binary_context.ParseFromString(msg_data)
                    
                    # Verify binary hash
                    if binary_context.metadata.sha256 != self.sha256_hash:
                        print(f"Warning: BCC file is for a different binary.")
                        print(f"BCC SHA256: {binary_context.metadata.sha256}")
                        print(f"Current binary SHA256: {self.sha256_hash}")
                        
                        if not binaryninja.interaction.show_message_box(
                            "SHA256 Mismatch",
                            "The BCC file is for a different binary. Import anyway?",
                            binaryninja.MessageBoxButtonSet.YesNoButtonSet
                        ):
                            print("Import cancelled")
                            return {"status": "cancelled"}
                    
                    print(f"Found binary context: {binary_context.metadata.binary_name}")
                    print(f"BCC version: {binary_context.metadata.bcc_version}")
                    
                elif msg_type == MessageType.FUNCTION_CONTEXT.value:
                    func_context = fc_pb.FunctionContext()
                    func_context.ParseFromString(msg_data)
                    function_contexts.append(func_context)
            
            if binary_context is None:
                print("No valid binary context found in file")
                return {"status": "error", "reason": "No binary context found"}
            
            print(f"Found {len(function_contexts)} function contexts")
            
            # Apply the imported data to the binary
            results = self._apply_imported_data(binary_context, function_contexts)
            return {"status": "success", "results": results}
            
        except Exception as e:
            print(f"Error importing BCC: {e}")
            return {"status": "error", "reason": str(e)}

# Update import_bcc function to use the class method
def import_bcc(bv):
    """Import a BCC file and apply analysis to current binary if matching"""
    # Ask for input file
    input_file = binaryninja.get_open_filename_input("Open BCC file", "*.bcc")
    if not input_file:
        print("Import cancelled")
        return
    
    exporter = BlackfyreBinaryNinjaExporter(bv)
    result = exporter.import_bcc(input_file)
    
    if result["status"] == "success":
        print("Import completed successfully")
        binaryninja.interaction.show_message_box(
            "Import Successful", 
            "BCC data was successfully imported and applied.",
            binaryninja.MessageBoxButtonSet.OKButtonSet
        )
    elif result["status"] == "error":
        print(f"Import failed: {result['reason']}")
        binaryninja.interaction.show_message_box(
            "Import Failed", 
            f"Error importing BCC data: {result['reason']}",
            binaryninja.MessageBoxButtonSet.OKButtonSet
        )

# Register plugin command
def export_bcc(bv):
    exporter = BlackfyreBinaryNinjaExporter(bv)
    
    # Show options dialog
    dialog = BlackfyreOptionsDialog()
    if not dialog.exec_modal():
        print("Export cancelled")
        return
    
    options = dialog.getResult()
    
    # Ask for output path
    output_file = binaryninja.get_save_filename_input("Save BCC file as", "*.bcc")
    if not output_file:
        print("Export cancelled")
        return
    
    # Export with selected options
    try:
        result_path = exporter.export_to_bcc(
            output_file, 
            options['include_raw'],
            options['extended_analysis']
        )
        print(f"Successfully exported to {result_path}")
    except Exception as e:
        print(f"Error exporting: {e}")

class BlackfyreOptionsDialog(binaryninja.interaction.FormDialog):
    """Dialog for configuring export options"""
    def __init__(self):
        super(BlackfyreOptionsDialog, self).__init__()
        self.include_raw = True
        self.extended_analysis = True
        
    def initializeView(self, view):
        self.setWindowTitle("Blackfyre Export Options")
        
        layout = binaryninja.interaction.FormLayout()
        layout.addRow("Include Raw Binary", self.createCheckBox(lambda: self.include_raw, lambda v: setattr(self, 'include_raw', v)))
        layout.addRow("Extended Analysis", self.createCheckBox(lambda: self.extended_analysis, lambda v: setattr(self, 'extended_analysis', v)))
        
        self.setLayout(layout)
        
    def getResult(self):
        return {
            'include_raw': self.include_raw,
            'extended_analysis': self.extended_analysis
        }

# Register plugin commands
binaryninja.plugin.PluginCommand.register(
    "Blackfyre\\Export BCC", 
    "Export Binary Ninja analysis to Blackfyre Binary Context Container (BCC) format", 
    export_bcc
)

binaryninja.plugin.PluginCommand.register(
    "Blackfyre\\Import BCC",
    "Import a Blackfyre Binary Context Container (BCC) file",
    import_bcc
)
