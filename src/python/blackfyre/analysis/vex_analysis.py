"""VEX IR-based program analysis capabilities"""

from typing import Dict, List, Set, Optional, Tuple, Any, Union
import pyvex
import archinfo
from blackfyre.datatypes.contexts.binarycontext import BinaryContext
from blackfyre.datatypes.contexts.functioncontext import FunctionContext
from blackfyre.datatypes.contexts.vex.vexfunctioncontext import VexFunctionContext

class DataFlowAnalyzer:
    """Analyze data flow in functions using VEX IR"""
    
    def __init__(self, binary_context: BinaryContext):
        """Initialize the data flow analyzer
        
        Args:
            binary_context: The BinaryContext to analyze
        """
        self.binary_context = binary_context
    
    def analyze_function(self, function_addr: int) -> Dict[str, Any]:
        """Analyze data flow in a function
        
        Args:
            function_addr: Address of the function to analyze
            
        Returns:
            Dictionary of analysis results
        """
        # Get function and ensure it's lifted to VEX IR
        if function_addr not in self.binary_context.function_context_dict:
            raise ValueError(f"Function not found at address {hex(function_addr)}")
        
        function = self.binary_context.function_context_dict[function_addr]
        
        # Convert to VexFunctionContext if needed
        if not isinstance(function, VexFunctionContext):
            function = VexFunctionContext.from_function_context(function)
            if not function.initialize():
                raise ValueError(f"Failed to initialize VexFunctionContext for function at {hex(function_addr)}")
        
        # Extract data flow information
        results = {
            "address": function_addr,
            "name": function.name,
            "register_usage": self._analyze_register_usage(function),
            "memory_access": self._analyze_memory_access(function),
            "constants": self._extract_constants(function),
            "call_args": self._analyze_call_arguments(function),
            "return_value": self._analyze_return_value(function),
        }
        
        return results
    
    def _analyze_register_usage(self, function: VexFunctionContext) -> Dict[str, Any]:
        """Analyze register usage in a function
        
        Args:
            function: The VexFunctionContext to analyze
            
        Returns:
            Dictionary of register usage information
        """
        reads = set()
        writes = set()
        
        # Analyze register usage in each block
        for bb_addr in function.get_basic_block_addresses():
            block = function.get_vex_basic_block(bb_addr)
            if not block:
                continue
            
            # Process statements in VEX IR block
            for stmt in block.statements:
                # Track register reads
                if hasattr(stmt, 'expressions'):
                    for expr in stmt.expressions:
                        if hasattr(expr, 'tag') and expr.tag == 'Iex_Get':
                            reg_name = function.get_arch().translate_register_name(expr.offset, expr.result_size(block.tyenv) // 8)
                            if reg_name:
                                reads.add(reg_name)
                
                # Track register writes
                if hasattr(stmt, 'tag') and stmt.tag == 'Ist_Put':
                    reg_name = function.get_arch().translate_register_name(stmt.offset, stmt.data.result_size(block.tyenv) // 8)
                    if reg_name:
                        writes.add(reg_name)
        
        return {
            "reads": sorted(list(reads)),
            "writes": sorted(list(writes)),
            "read_count": len(reads),
            "write_count": len(writes),
            "read_write": sorted(list(reads.intersection(writes))),
        }
    
    def _analyze_memory_access(self, function: VexFunctionContext) -> Dict[str, Any]:
        """Analyze memory accesses in a function
        
        Args:
            function: The VexFunctionContext to analyze
            
        Returns:
            Dictionary of memory access information
        """
        loads = []
        stores = []
        
        # Analyze memory access in each block
        for bb_addr in function.get_basic_block_addresses():
            block = function.get_vex_basic_block(bb_addr)
            if not block:
                continue
            
            # Process statements in VEX IR block
            for stmt_idx, stmt in enumerate(block.statements):
                # Track memory loads
                if hasattr(stmt, 'tag') and stmt.tag == 'Ist_WrTmp' and hasattr(stmt.data, 'tag') and stmt.data.tag == 'Iex_Load':
                    loads.append({
                        "block_addr": bb_addr,
                        "stmt_idx": stmt_idx,
                        "size": stmt.data.result_size(block.tyenv) // 8
                    })
                
                # Track memory stores
                if hasattr(stmt, 'tag') and stmt.tag == 'Ist_Store':
                    stores.append({
                        "block_addr": bb_addr,
                        "stmt_idx": stmt_idx,
                        "size": stmt.data.result_size(block.tyenv) // 8
                    })
        
        return {
            "loads": loads,
            "stores": stores,
            "load_count": len(loads),
            "store_count": len(stores),
        }
    
    def _extract_constants(self, function: VexFunctionContext) -> List[int]:
        """Extract constants used in a function
        
        Args:
            function: The VexFunctionContext to analyze
            
        Returns:
            List of constants
        """
        constants = set()
        
        # Extract constants from each block
        for bb_addr in function.get_basic_block_addresses():
            block = function.get_vex_basic_block(bb_addr)
            if not block:
                continue
            
            # Process statements in VEX IR block
            for stmt in block.statements:
                if hasattr(stmt, 'expressions'):
                    for expr in stmt.expressions:
                        if hasattr(expr, 'tag') and expr.tag == 'Iex_Const':
                            # Extract the constant value
                            if hasattr(expr.con, 'value'):
                                constants.add(expr.con.value)
        
        return sorted(list(constants))
    
    def _analyze_call_arguments(self, function: VexFunctionContext) -> Dict[int, List[Dict[str, Any]]]:
        """Analyze arguments to function calls
        
        Args:
            function: The VexFunctionContext to analyze
            
        Returns:
            Dictionary mapping call sites to argument information
        """
        call_args = {}
        
        # Get call sites
        call_sites = function.get_all_callee_call_sites()
        if not call_sites:
            return {}
        
        # Analyze each call site
        for callee_addr, sites in call_sites.items():
            for site in sites:
                # This is a simplified version - in reality, argument analysis
                # requires more complex analysis of the VEX IR prior to the call
                call_args[site] = {
                    "callee": callee_addr,
                    "args": []  # Would contain register/stack locations used for args
                }
        
        return call_args
    
    def _analyze_return_value(self, function: VexFunctionContext) -> Dict[str, Any]:
        """Analyze return value handling in a function
        
        Args:
            function: The VexFunctionContext to analyze
            
        Returns:
            Dictionary of return value information
        """
        # This is a simplified version - in reality, return value analysis
        # requires tracking what's placed in the return register before ret instructions
        return {
            "has_return": self._has_return_instruction(function),
            "return_register": self._get_return_register_name(function.get_arch())
        }
    
    def _has_return_instruction(self, function: VexFunctionContext) -> bool:
        """Check if function has a return instruction
        
        Args:
            function: The VexFunctionContext to analyze
            
        Returns:
            True if function has a return instruction
        """
        # Look for return statements in the VEX IR
        for bb_addr in function.get_basic_block_addresses():
            block = function.get_vex_basic_block(bb_addr)
            if not block:
                continue
            
            # Check if this block ends with a return
            if hasattr(block.next, 'tag') and block.next.tag == 'Iex_RdTmp':
                return True
        
        return False
    
    def _get_return_register_name(self, arch: archinfo.Arch) -> str:
        """Get the name of the register used for return values
        
        Args:
            arch: The architecture
            
        Returns:
            Name of the return register
        """
        # Return register conventions by architecture
        if isinstance(arch, archinfo.ArchAMD64):
            return "rax"
        elif isinstance(arch, archinfo.ArchX86):
            return "eax"
        elif isinstance(arch, archinfo.ArchARM):
            return "r0"
        elif isinstance(arch, archinfo.ArchAArch64):
            return "x0"
        elif isinstance(arch, archinfo.ArchMIPS32):
            return "v0"
        else:
            return "unknown"


class SymbolicExecutor:
    """Simple symbolic execution engine for VEX IR"""
    
    def __init__(self, binary_context: BinaryContext):
        """Initialize the symbolic executor
        
        Args:
            binary_context: The BinaryContext to analyze
        """
        self.binary_context = binary_context
        self.constraints = []
        self.symbolic_vars = {}
        self.memory_model = {}
        self.register_values = {}
    
    def symbolically_execute_function(self, function_addr: int, max_paths: int = 10) -> Dict[str, Any]:
        """Symbolically execute a function
        
        Args:
            function_addr: Address of the function to analyze
            max_paths: Maximum number of paths to explore
            
        Returns:
            Dictionary of symbolic execution results
        """
        # Get function and ensure it's lifted to VEX IR
        if function_addr not in self.binary_context.function_context_dict:
            raise ValueError(f"Function not found at address {hex(function_addr)}")
        
        function = self.binary_context.function_context_dict[function_addr]
        
        # Convert to VexFunctionContext if needed
        if not isinstance(function, VexFunctionContext):
            function = VexFunctionContext.from_function_context(function)
            if not function.initialize():
                raise ValueError(f"Failed to initialize VexFunctionContext for function at {hex(function_addr)}")
        
        # In a real implementation, we would perform symbolic execution here
        # This is a placeholder that returns some basic information
        return {
            "address": function_addr,
            "name": function.name,
            "paths_explored": min(len(function.basic_block_contexts), max_paths),
            "potential_conditions": self._identify_branch_conditions(function),
            "potential_loops": self._identify_loops(function),
        }
    
    def _identify_branch_conditions(self, function: VexFunctionContext) -> List[Dict[str, Any]]:
        """Identify branch conditions in the function
        
        Args:
            function: The VexFunctionContext to analyze
            
        Returns:
            List of branch condition information
        """
        conditions = []
        
        for bb_addr in function.get_basic_block_addresses():
            block = function.get_vex_basic_block(bb_addr)
            if not block:
                continue
            
            # Check if block ends with a conditional exit
            if hasattr(block, 'jumpkind') and block.jumpkind == 'Ijk_Boring':
                if len(block.next_constants) > 1:
                    conditions.append({
                        "block_addr": bb_addr,
                        "target_true": block.next_constants[0].value,  # Simplification
                        "target_false": block.next_constants[1].value  # Simplification
                    })
        
        return conditions
    
    def _identify_loops(self, function: VexFunctionContext) -> List[Dict[str, Any]]:
        """Identify potential loops in the function
        
        Args:
            function: The VexFunctionContext to analyze
            
        Returns:
            List of potential loop information
        """
        # Simple loop detection - find basic blocks that can reach themselves
        potential_loops = []
        
        # Build CFG as adjacency list
        cfg = {}
        for bb_addr in function.get_basic_block_addresses():
            block = function.get_vex_basic_block(bb_addr)
            if not block:
                continue
                
            # Get successor blocks
            successors = []
            for const in block.next_constants:
                successors.append(const.value)
                
            cfg[bb_addr] = successors
        
        # Find blocks that can reach themselves (directly or indirectly)
        for start_addr in cfg:
            visited = set()
            stack = [start_addr]
            
            while stack:
                current = stack.pop()
                if current in visited:
                    continue
                    
                visited.add(current)
                
                if current in cfg:
                    for succ in cfg[current]:
                        if succ == start_addr:  # Loop back to start
                            potential_loops.append({
                                "header_addr": start_addr,
                                "type": "natural" if len(cfg.get(current, [])) > 1 else "unconditional"
                            })
                            break
                        stack.append(succ)
        
        return potential_loops
