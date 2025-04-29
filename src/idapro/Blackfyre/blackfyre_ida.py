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
    
    def _collect_basic_blocks(self, func_addr):
        """Collect basic block information for a function"""
        blocks = []
        
        # Get function object
        func = ida_funcs.get_func(func_addr)
        if not func:
            return blocks
            
        # Create flowchart for the function
        flow_chart = idaapi.FlowChart(func)
        
        # For each basic block in the flowchart
        for block in flow_chart:
            # Collect incoming and outgoing edges
            incoming_edges = []
            outgoing_edges = []
            
            for pred_block in block.preds():
                incoming_edges.append(pred_block.start_ea)
                
            for succ_block in block.succs():
                outgoing_edges.append(succ_block.start_ea)
            
            # Collect instructions in this block
            instructions = []
            current_addr = block.start_ea
            
            while current_addr < block.end_ea:
                # Get instruction disassembly
                disasm = idaapi.generate_disasm_line(current_addr, 0)
                mnemonic = idaapi.print_insn_mnem(current_addr)
                
                # Get operand information
                operands = []
                
                for i in range(5):  # Check up to 5 operands (IDA's limit is usually 4)
                    op_type = idaapi.get_operand_type(current_addr, i)
                    if op_type == idaapi.o_void:
                        break  # No more operands
                    
                    op_value = None
                    op_is_address = False
                    
                    # Extract operand value based on type
                    if op_type in [idaapi.o_imm, idaapi.o_mem]:
                        op_value = idaapi.get_operand_value(current_addr, i)
                        op_is_address = op_type == idaapi.o_mem
                    
                    # For immediate values, check if they point to strings
                    if op_type == idaapi.o_imm:
                        if ida_bytes.is_strlit(ida_bytes.get_flags(op_value)):
                            op_string = ida_bytes.get_strlit_contents(op_value, -1, 0)
                            if op_string:
                                operands.append({
                                    "type": "immediate",
                                    "value": op_value,
                                    "is_address": False,
                                    "string_value": op_string.decode('utf-8', errors='replace')
                                })
                                continue
                    
                    # For memory references, check if they point to strings
                    if op_type == idaapi.o_mem:
                        if ida_bytes.is_strlit(ida_bytes.get_flags(op_value)):
                            op_string = ida_bytes.get_strlit_contents(op_value, -1, 0)
                            if op_string:
                                operands.append({
                                    "type": "memory",
                                    "value": op_value,
                                    "is_address": True,
                                    "string_value": op_string.decode('utf-8', errors='replace')
                                })
                                continue
                    
                    # Standard operand
                    operands.append({
                        "type": self._get_operand_type_name(op_type),
                        "value": op_value,
                        "is_address": op_is_address
                    })
                
                # Get any data/code references from this instruction
                data_refs = list(idautils.DataRefsFrom(current_addr))
                code_refs = list(idautils.CodeRefsFrom(current_addr, 0))
                
                instructions.append({
                    "address": current_addr,
                    "disassembly": disasm,
                    "mnemonic": mnemonic,
                    "operands": operands,
                    "data_refs": data_refs,
                    "code_refs": code_refs
                })
                
                # Move to next instruction
                current_addr = idc.next_head(current_addr)
            
            # Determine if this block contains a call instruction
            has_call = any(idaapi.is_call_insn(instr["address"]) for instr in instructions)
            
            blocks.append({
                "start_address": block.start_ea,
                "end_address": block.end_ea,
                "incoming_edges": incoming_edges,
                "outgoing_edges": outgoing_edges,
                "instructions": instructions,
                "has_call": has_call
            })
        
        return blocks
    
    def _get_operand_type_name(self, op_type):
        """Convert IDA operand type to readable name"""
        op_types = {
            idaapi.o_void: "void",
            idaapi.o_reg: "register",
            idaapi.o_mem: "memory",
            idaapi.o_phrase: "phrase",
            idaapi.o_displ: "displacement",
            idaapi.o_imm: "immediate",
            idaapi.o_far: "far",
            idaapi.o_near: "near"
        }
        return op_types.get(op_type, "unknown")
    
    def _collect_function_cross_references(self, func_addr):
        """Collect cross-references to a function"""
        xrefs = []
        
        # Get all references to this function
        for xref in idautils.XrefsTo(func_addr):
            ref_func = ida_funcs.get_func(xref.frm)
            
            # Try to get the instruction at this reference
            instr = idaapi.generate_disasm_line(xref.frm, 0)
            
            xrefs.append({
                "address": xref.frm,
                "function": ida_name.get_name(ref_func.start_ea) if ref_func else "unknown",
                "instruction": instr,
                "is_call": xref.type == idaapi.fl_CN or xref.type == idaapi.fl_CF
            })
        
        return xrefs
    
    def _get_decompiled_code(self, func_addr):
        """Get decompiled code if Hex-Rays is available"""
        try:
            # Check if Hex-Rays is available
            if not idaapi.init_hexrays_plugin():
                return None
                
            func = ida_funcs.get_func(func_addr)
            if not func:
                return None
                
            # Get decompiled function
            cfunc = idaapi.decompile(func)
            if cfunc:
                return str(cfunc)
        except:
            pass
        return None
    
    def _collect_data_variables(self):
        """Collect data variables and their references"""
        data_vars = []
        
        # Iterate through segments
        for seg_ea in idautils.Segments():
            for head in idautils.Heads(seg_ea, idc.get_segm_end(seg_ea)):
                # Skip if this is an instruction
                if idaapi.is_code(ida_bytes.get_flags(head)):
                    continue
                    
                # This is data
                name = ida_name.get_name(head)
                if not name:
                    continue  # Skip unnamed data
                
                # Get type information
                tinfo = idaapi.tinfo_t()
                var_type = "unknown"
                if idaapi.get_tinfo(tinfo, head):
                    var_type = str(tinfo)
                    
                # Get value if possible
                value = None
                size = idc.get_item_size(head)
                if size > 0 and size <= 8:
                    try:
                        value = idc.get_bytes(head, size).hex()
                    except:
                        pass
                
                # Get cross-references
                xrefs = list(idautils.XrefsTo(head))
                xrefs_addrs = [xref.frm for xref in xrefs]
                
                data_vars.append({
                    "address": head,
                    "name": name,
                    "type": var_type,
                    "value": value,
                    "xrefs": xrefs_addrs
                })
        
        return data_vars
    
    def _collect_sections(self):
        """Collect section information"""
        sections = []
        
        for seg_idx in range(idaapi.get_segm_qty()):
            seg = idaapi.getnseg(seg_idx)
            if not seg:
                continue
                
            sections.append({
                "name": idaapi.get_segm_name(seg),
                "start_address": seg.start_ea,
                "end_address": seg.end_ea,
                "readable": (seg.perm & idaapi.SEGPERM_READ) != 0,
                "writable": (seg.perm & idaapi.SEGPERM_WRITE) != 0,
                "executable": (seg.perm & idaapi.SEGPERM_EXEC) != 0
            })
        
        return sections
    
    def _collect_extended_function_info(self, functions, caller_to_callees):
        """Collect extended information for functions"""
        extended_functions = []
        
        for func_info in functions:
            func_addr = func_info["start_address"]
            func = ida_funcs.get_func(func_addr)
            if not func:
                extended_functions.append(func_info)
                continue
                
            # Get basic blocks
            basic_blocks = self._collect_basic_blocks(func_addr)
            
            # Get cross-references to this function
            xrefs = self._collect_function_cross_references(func_addr)
            
            # Get decompiled code if available
            decompiled = self._get_decompiled_code(func_addr)
            
            # Add analysis flags and metadata
            analysis_info = {
                "is_library": (func.flags & ida_funcs.FUNC_LIB) != 0,
                "has_unresolved_calls": any(callee == 0 for callee in caller_to_callees.get(func_addr, [])),
                "is_imported": idaapi.is_imported_func(func),
                "is_exported": idaapi.is_public_name(func_addr),
                "stack_frame_size": idaapi.get_frame_size(func),
                "has_loops": any(block["start_address"] in block["incoming_edges"] for block in basic_blocks),
                "call_convention": self._get_calling_convention(func)
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
    
    def _get_calling_convention(self, func):
        """Get calling convention of a function"""
        cc = func.cc
        
        # Map IDA's calling convention values to names
        cc_names = {
            idaapi.CM_CC_INVALID: "invalid",
            idaapi.CM_CC_CDECL: "cdecl",
            idaapi.CM_CC_STDCALL: "stdcall",
            idaapi.CM_CC_ELLIPSIS: "ellipsis",
            idaapi.CM_CC_THISCALL: "thiscall", 
            idaapi.CM_CC_FASTCALL: "fastcall",
        }
        
        return cc_names.get(cc & idaapi.CM_CC_MASK, "unknown")
    
    def _get_architecture_specific_info(self):
        """Get architecture-specific information"""
        arch_info = {}
        info = idaapi.get_inf_structure()
        
        if info.procname == "metapc":
            arch_info["instruction_set"] = "x86"
            arch_info["extensions"] = []
            
            # Check for extensions (simplified approach - would be more complex in real implementation)
            for func in idautils.Functions():
                for instr_addr in idautils.FuncItems(func):
                    mnem = idaapi.print_insn_mnem(instr_addr)
                    if "sse" in mnem.lower() and "SSE" not in arch_info["extensions"]:
                        arch_info["extensions"].append("SSE")
                    if "avx" in mnem.lower() and "AVX" not in arch_info["extensions"]:
                        arch_info["extensions"].append("AVX")
        
        elif info.procname == "ARM":
            arch_info["instruction_set"] = "ARM"
            if info.is_64bit():
                arch_info["extensions"] = ["AArch64"]
            else:
                # Check for Thumb mode
                arch_info["extensions"] = []
                for func in idautils.Functions():
                    func_obj = ida_funcs.get_func(func)
                    if func_obj and (func_obj.flags & idaapi.FUNC_THUMB) != 0:
                        arch_info["extensions"].append("Thumb")
                        break
        
        elif info.procname == "mipsb" or info.procname == "mipsl":
            arch_info["instruction_set"] = "MIPS"
            arch_info["extensions"] = []
            
        elif info.procname == "ppc":
            arch_info["instruction_set"] = "PowerPC"
            arch_info["extensions"] = []
        
        return arch_info

    def _apply_imported_data(self, binary_context, function_contexts):
        """Apply imported BCC data to the current database"""
        print("Applying imported BCC data...")
        
        # Track what's been applied
        applied_count = {
            "comments": 0,
            "function_names": 0,
            "types": 0
        }
        
        # Apply binary-level information
        if binary_context:
            # Import strings
            for string_ref in binary_context.strings:
                if ida_bytes.is_loaded(string_ref.address):
                    # Add a comment for the string
                    idaapi.set_cmt(string_ref.address, f"String: {string_ref.value}", 0)
                    applied_count["comments"] += 1
        
        # Apply function-level information
        for func_ctx in function_contexts:
            # Find matching function by address
            func = ida_funcs.get_func(func_ctx.start_address)
            if not func:
                continue
            
            # Apply function name if it's more specific (not like sub_X)
            current_name = ida_name.get_name(func_ctx.start_address)
            imported_name = func_ctx.name
            if imported_name and not imported_name.startswith("sub_") and current_name.startswith("sub_"):
                idaapi.set_name(func_ctx.start_address, imported_name)
                applied_count["function_names"] += 1
            
            # Add function comment with source info
            idaapi.set_func_cmt(func, f"Imported from BCC - {func_ctx.name}", 0)
            
            # Apply decompiled code as comment if available
            if func_ctx.decompiled_code:
                idaapi.set_func_cmt(func, f"Decompiled Code:\n{func_ctx.decompiled_code[:500]}...", 0)
                applied_count["comments"] += 1
            
            # Apply basic block information
            for bb in func_ctx.basic_blocks:
                # Add comment at the start of each basic block
                idaapi.set_cmt(bb.start_address, f"Block from {func_ctx.name}", 0)
                applied_count["comments"] += 1
                
        print(f"Applied data from BCC:")
        print(f"- {applied_count['comments']} comments")
        print(f"- {applied_count['function_names']} function names")
        print(f"- {applied_count['types']} types")
            
        return applied_count

    def import_bcc(self, input_path):
        """Import a BCC file and apply analysis to current database
        
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
                        
                        if idaapi.ask_yn(idaapi.ASKBTN_NO, "The BCC file is for a different binary. Import anyway?") == idaapi.ASKBTN_NO:
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
    
    def export_to_bcc(self, output_path=None, include_raw_binary=True, extended_analysis=True):
        """Export IDA analysis to BCC format
        
        Args:
            output_path: Path to save the BCC file (default: same as IDB but with .bcc extension)
            include_raw_binary: Whether to include the raw binary in the BCC
            extended_analysis: Whether to include extended analysis data
            
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
            
            print("- Getting architecture-specific information")
            arch_info = self._get_architecture_specific_info()
        
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
        binary_context.metadata.tool_name = "IDA Pro"
        binary_context.metadata.tool_version = idaapi.get_kernel_version()
        
        # Add additional metadata if available
        info = idaapi.get_inf_structure()
        binary_context.metadata.entry_point = info.start_ea
        
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
                    callee_name = ida_name.get_name(callee)
                    if callee_name:
                        callee_ref.name = callee_name
            
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
                        if "mnemonic" in instr:
                            instruction.mnemonic = instr["mnemonic"]
                
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
        
        print(f"Writing BCC file to: {output_path}")
        
        # Write the BCC file
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
                        callee_name = ida_name.get_name(callee)
                        if callee_name:
                            callee_ref.name = callee_name
                
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
                            if "mnemonic" in instr:
                                instruction.mnemonic = instr["mnemonic"]
                    
                    # Add decompiled code if available
                    if func.get("decompiled"):
                        func_context.decompiled_code = func["decompiled"]
                
                # Serialize and write TLV
                func_bytes = func_context.SerializeToString()
                f.write(struct.pack('!II', MessageType.FUNCTION_CONTEXT.value, len(func_bytes)))
                f.write(func_bytes)
            
            # Include raw binary if requested
            if include_raw_binary:
                binary_path = idaapi.get_input_file_path()
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

# Modified IDA Plugin setup to include import functionality
class BlackfyrePlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Export IDA analysis to Blackfyre BCC format"
    help = "Exports IDA analysis to the Blackfyre Binary Context Container format"
    wanted_name = "Blackfyre BCC Export"
    wanted_hotkey = "Ctrl-Alt-B"
    
    def init(self):
        print("Blackfyre IDA Plugin initialized")
        self._add_menu_items()
        return idaapi.PLUGIN_OK
        
    def run(self, arg):
        self._export_bcc()
        
    def term(self):
        self._remove_menu_items()
        
    def _add_menu_items(self):
        # Create Blackfyre menu
        menu = idaapi.add_menu_item("File/", "Blackfyre", "Blackfyre", 0, self._dummy, None)
        
        # Add export item
        idaapi.add_menu_item("File/Blackfyre/", "Export BCC...", "Export BCC", 0, self._export_bcc, None)
        
        # Add import item
        idaapi.add_menu_item("File/Blackfyre/", "Import BCC...", "Import BCC", 0, self._import_bcc, None)
    
    def _remove_menu_items(self):
        idaapi.del_menu_item("File/Blackfyre/Export BCC...")
        idaapi.del_menu_item("File/Blackfyre/Import BCC...")
        idaapi.del_menu_item("File/Blackfyre")
    
    def _dummy(self):
        pass
    
    def _export_bcc(self):
        exporter = BlackfyreIDAExporter()
        
        # Ask for options
        include_raw = idaapi.ask_yn(1, "Include raw binary data in the BCC file?") == 1
        extended_analysis = idaapi.ask_yn(1, "Include extended analysis data (may take longer)?") == 1
        
        # Ask for output path
        output_path = idaapi.ask_file(1, "*.bcc", "Save BCC file as")
        if not output_path:
            print("Export cancelled")
            return
            
        # Export
        try:
            result_path = exporter.export_to_bcc(output_path, include_raw, extended_analysis)
            print(f"Successfully exported to {result_path}")
        except Exception as e:
            print(f"Error exporting: {e}")
    
    def _import_bcc(self):
        exporter = BlackfyreIDAExporter()
        
        # Ask for input path
        input_path = idaapi.ask_file(0, "*.bcc", "Open BCC file")
        if not input_path:
            print("Import cancelled")
            return
            
        # Import
        try:
            result = exporter.import_bcc(input_path)
            if result["status"] == "success":
                print("Import completed successfully")
            elif result["status"] == "error":
                print(f"Import failed: {result['reason']}")
        except Exception as e:
            print(f"Error importing: {e}")

def PLUGIN_ENTRY():
    return BlackfyrePlugin()
