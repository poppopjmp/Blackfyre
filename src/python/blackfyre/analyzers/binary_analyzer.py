"""
Binary Analyzer - High level analysis of binary files using Blackfyre.
"""

import logging
import os
from typing import Dict, List, Optional, Set, Tuple, Any, Union
from collections import Counter

from blackfyre.datatypes.contexts.binarycontext import BinaryContext
from blackfyre.utils import setup_custom_logger

logger = setup_custom_logger("BinaryAnalyzer")

class BinaryAnalyzer:
    """
    Main analyzer class for binary files. Provides high-level analysis
    capabilities for binaries loaded into a BinaryContext.
    """
    
    def __init__(self, binary_context: BinaryContext):
        """
        Initialize the analyzer with a binary context.
        
        Args:
            binary_context: The BinaryContext to analyze
        """
        self.binary_context = binary_context
        self.logger = logger
        
        # Cache for analysis results
        self._analysis_cache = {}
        
        # Initialize with basic analysis
        self._init_analysis()
    
    def _init_analysis(self):
        """Run initial analysis to populate basic metrics."""
        self.logger.info(f"Initializing analysis for {self.binary_context.name}")
        
        # Basic stats
        self.function_count = len(self.binary_context.function_context_dict)
        self.import_count = len(self.binary_context.import_symbols)
        self.export_count = len(self.binary_context.export_symbols)
        self.string_count = len(self.binary_context.string_refs)
        
        self.logger.info(f"Binary has {self.function_count} functions, {self.import_count} imports, "
                         f"{self.export_count} exports, and {self.string_count} strings")
    
    def get_basic_stats(self) -> Dict[str, Any]:
        """
        Get basic statistics about the binary.
        
        Returns:
            Dictionary with basic stats
        """
        return {
            "name": self.binary_context.name,
            "sha256": self.binary_context.sha256_hash,
            "architecture": self.binary_context.proc_type,
            "file_type": self.binary_context.file_type,
            "function_count": self.function_count,
            "import_count": self.import_count,
            "export_count": self.export_count,
            "string_count": self.string_count,
        }
    
    def get_imported_libraries(self) -> Dict[str, List[str]]:
        """
        Get imported libraries and their functions.
        
        Returns:
            Dictionary mapping library names to lists of imported function names
        """
        if "imported_libraries" in self._analysis_cache:
            return self._analysis_cache["imported_libraries"]
        
        libraries = {}
        for symbol in self.binary_context.import_symbols:
            if symbol.library_name not in libraries:
                libraries[symbol.library_name] = []
            libraries[symbol.library_name].append(symbol.name)
        
        self._analysis_cache["imported_libraries"] = libraries
        return libraries
    
    def find_crypto_functions(self) -> List[Tuple[int, str]]:
        """
        Identify potential cryptographic functions.
        
        Returns:
            List of (address, function_name) tuples for likely crypto functions
        """
        if "crypto_functions" in self._analysis_cache:
            return self._analysis_cache["crypto_functions"]
        
        # Common crypto-related keywords
        crypto_keywords = [
            "aes", "des", "rsa", "sha", "md5", "crypt", "decrypt", "encrypt",
            "hash", "hmac", "cipher", "ssl", "tls", "blowfish", "rc4", "rc5",
            "rc6", "3des", "tripledes", "elliptic", "ecc", "ecdsa", "signature"
        ]
        
        crypto_functions = []
        
        # Check function names
        for addr, func in self.binary_context.function_context_dict.items():
            func_name = func.name.lower()
            if any(keyword in func_name for keyword in crypto_keywords):
                crypto_functions.append((addr, func.name))
                continue
            
            # Check for strings related to crypto
            if hasattr(func, 'string_refs'):
                for _, string_val in func.string_refs.items():
                    if any(keyword in string_val.lower() for keyword in crypto_keywords):
                        crypto_functions.append((addr, func.name))
                        break
        
        self._analysis_cache["crypto_functions"] = crypto_functions
        return crypto_functions
    
    def find_network_functions(self) -> List[Tuple[int, str]]:
        """
        Identify potential network-related functions.
        
        Returns:
            List of (address, function_name) tuples for likely network functions
        """
        if "network_functions" in self._analysis_cache:
            return self._analysis_cache["network_functions"]
        
        # Network-related keywords and import names
        network_keywords = [
            "socket", "connect", "bind", "listen", "accept", "recv", "send",
            "http", "https", "ftp", "ssh", "tcp", "udp", "dns", "url", "uri",
            "ip", "host", "port", "network", "packet", "wsock", "winsock"
        ]
        
        network_functions = []
        
        # Check imports first (more reliable)
        network_imports = set()
        for symbol in self.binary_context.import_symbols:
            if any(keyword in symbol.name.lower() for keyword in network_keywords):
                network_imports.add(symbol.name)
        
        # Check functions that call network imports or have network names
        for addr, func in self.binary_context.function_context_dict.items():
            func_name = func.name.lower()
            
            # Check function name
            if any(keyword in func_name for keyword in network_keywords):
                network_functions.append((addr, func.name))
                continue
            
            # Check for network imports called by this function
            if hasattr(func, 'callees'):
                for callee_addr in func.callees:
                    if callee_addr in self.binary_context.function_context_dict:
                        callee = self.binary_context.function_context_dict[callee_addr]
                        if callee.name in network_imports:
                            network_functions.append((addr, func.name))
                            break
            
            # Check for strings related to networking
            if hasattr(func, 'string_refs'):
                for _, string_val in func.string_refs.items():
                    # Check for URLs, IPs, etc.
                    if any(keyword in string_val.lower() for keyword in network_keywords):
                        network_functions.append((addr, func.name))
                        break
        
        self._analysis_cache["network_functions"] = network_functions
        return network_functions
    
    def detect_obfuscation(self) -> Dict[str, Any]:
        """
        Detect potential code obfuscation techniques.
        
        Returns:
            Dictionary with obfuscation analysis results
        """
        if "obfuscation_analysis" in self._analysis_cache:
            return self._analysis_cache["obfuscation_analysis"]
        
        results = {
            "likely_obfuscated": False,
            "indicators": [],
            "score": 0  # 0-100 scale
        }
        
        # Check for strings obfuscation (unusually low string count)
        if self.function_count > 100 and self.string_count < self.function_count * 0.1:
            results["indicators"].append("Low string count relative to function count")
            results["score"] += 20
        
        # Check for unusual function size distribution
        total_instructions = sum(func.total_instructions for func in self.binary_context.function_context_dict.values())
        if total_instructions > 0:
            avg_instructions = total_instructions / self.function_count
            
            # Collect deviation from avg
            large_functions = 0
            small_functions = 0
            for func in self.binary_context.function_context_dict.values():
                if func.total_instructions > avg_instructions * 5:
                    large_functions += 1
                elif func.total_instructions < avg_instructions * 0.2:
                    small_functions += 1
            
            # Unusual distribution of function sizes
            if large_functions > self.function_count * 0.2:
                results["indicators"].append("High number of abnormally large functions")
                results["score"] += 15
                
            if small_functions > self.function_count * 0.5:
                results["indicators"].append("High number of abnormally small functions")
                results["score"] += 15
        
        # Check for unusual instruction patterns
        jmp_heavy_functions = 0
        for _, func in self.binary_context.function_context_dict.items():
            jmp_count = 0
            instr_count = 0
            
            # Count jumps in basic blocks
            for bb in func.basic_block_contexts:
                for instr in bb.instruction_contexts:
                    instr_count += 1
                    if hasattr(instr, 'mnemonic'):
                        if instr.mnemonic.lower() in ('jmp', 'je', 'jne', 'jz', 'jnz', 'ja', 'jb'):
                            jmp_count += 1
            
            # If > 30% of instructions are jumps, that's unusual
            if instr_count > 0 and jmp_count / instr_count > 0.3:
                jmp_heavy_functions += 1
        
        if jmp_heavy_functions > self.function_count * 0.1:
            results["indicators"].append("High number of functions with excessive jump instructions")
            results["score"] += 25
            
        # Set overall likelihood based on score
        if results["score"] >= 50:
            results["likely_obfuscated"] = True
        
        self._analysis_cache["obfuscation_analysis"] = results
        return results
    
    def identify_entry_points(self) -> List[Tuple[int, str]]:
        """
        Identify likely program entry points.
        
        Returns:
            List of (address, function_name) tuples for likely entry points
        """
        if "entry_points" in self._analysis_cache:
            return self._analysis_cache["entry_points"]
        
        entry_points = []
        entry_keywords = ["main", "start", "entry", "_main", "winmain", "wmain", "_start", "__start"]
        
        # Look for common entry point names
        for addr, func in self.binary_context.function_context_dict.items():
            func_name = func.name.lower()
            if any(keyword in func_name for keyword in entry_keywords):
                entry_points.append((addr, func.name))
        
        # Look at exports if no entry points found
        if not entry_points:
            for symbol in self.binary_context.export_symbols:
                if any(keyword in symbol.name.lower() for keyword in entry_keywords):
                    entry_points.append((symbol.address, symbol.name))
        
        self._analysis_cache["entry_points"] = entry_points
        return entry_points
    
    def get_interesting_strings(self, limit: int = 100) -> List[Tuple[int, str]]:
        """
        Find interesting strings in the binary.
        
        Args:
            limit: Maximum number of strings to return
            
        Returns:
            List of (address, string) tuples for interesting strings
        """
        if "interesting_strings" in self._analysis_cache:
            return self._analysis_cache["interesting_strings"][:limit]
        
        interesting_patterns = [
            # URLs and network locations
            r"https?://", r"ftp://", r"www\.", r"\.com", r"\.net", r"\.org", 
            # File paths and extensions
            r"\.exe", r"\.dll", r"\.sys", r"\.bat", r"\.sh", r"\.py", r"\.dat", r"\\windows\\", r"/bin/", 
            # Configuration-related
            r"config", r"settings", r"options", r"registry",
            # Security-related
            r"password", r"key", r"encrypt", r"decrypt", r"hash", r"crypt", 
            # Command & control
            r"command", r"server", r"client", r"bot", r"agent", r"callback"
        ]
        
        import re
        
        # Compile regex patterns
        patterns = [re.compile(pattern, re.IGNORECASE) for pattern in interesting_patterns]
        
        # Match strings against patterns
        interesting_strings = []
        for addr, string_val in self.binary_context.string_refs.items():
            # Skip very short strings
            if len(string_val) < 4:
                continue
                
            # Skip very common strings
            if string_val.lower() in ["error", "success", "failed", "warning", "info", "debug"]:
                continue
                
            # Check against regex patterns
            if any(pattern.search(string_val) for pattern in patterns):
                interesting_strings.append((addr, string_val))
        
        # Sort by address and limit results
        interesting_strings.sort(key=lambda x: x[0])
        self._analysis_cache["interesting_strings"] = interesting_strings
        return interesting_strings[:limit]
    
    def analyze_function(self, addr: int) -> Dict[str, Any]:
        """
        Perform detailed analysis of a specific function.
        
        Args:
            addr: Function address
            
        Returns:
            Dictionary with function analysis results
        """
        if addr not in self.binary_context.function_context_dict:
            raise ValueError(f"Function not found at address 0x{addr:x}")
            
        function = self.binary_context.function_context_dict[addr]
        
        # Basic function info
        result = {
            "name": function.name,
            "address": addr,
            "size": function.end_address - function.start_address,
            "is_thunk": function.is_thunk,
            "basic_blocks": len(function.basic_block_contexts),
            "instructions": function.total_instructions,
            "complexity": self._calculate_function_complexity(function),
            "callees": [],
            "callers": [],
            "strings": []
        }
        
        # Get callees (functions called by this one)
        if hasattr(function, 'callees'):
            for callee_addr in function.callees:
                if callee_addr in self.binary_context.function_context_dict:
                    callee = self.binary_context.function_context_dict[callee_addr]
                    result["callees"].append({
                        "address": callee_addr,
                        "name": callee.name
                    })
        
        # Get callers (functions that call this one)
        result["callers"] = self._find_function_callers(addr)
        
        # Get strings referenced by this function
        if hasattr(function, 'string_refs'):
            for string_addr, string_val in function.string_refs.items():
                result["strings"].append({
                    "address": string_addr,
                    "value": string_val
                })
        
        return result
    
    def _calculate_function_complexity(self, function) -> float:
        """Calculate cyclomatic complexity for a function."""
        # Basic implementation based on number of basic blocks and edges
        if len(function.basic_block_contexts) <= 1:
            return 1.0
            
        # Estimate edges (in a more complete implementation, we would have actual edge info)
        edges = 0
        for bb in function.basic_block_contexts:
            if hasattr(bb, "successors"):
                edges += len(bb.successors)
            else:
                # Estimate based on last instruction
                if bb.instruction_contexts:
                    last_instr = bb.instruction_contexts[-1]
                    if hasattr(last_instr, 'mnemonic'):
                        mnemonic = last_instr.mnemonic.lower()
                        if mnemonic in ('jmp', 'je', 'jne', 'jz', 'jnz', 'ja', 'jb'):
                            edges += 2  # Conditional jump has two successors
                        else:
                            edges += 1  # Standard edge to next block
                    else:
                        edges += 1
                else:
                    edges += 1
        
        # Cyclomatic complexity formula: E - N + 2
        # Where E is edges and N is nodes (basic blocks)
        return edges - len(function.basic_block_contexts) + 2
    
    def _find_function_callers(self, target_addr: int) -> List[Dict[str, Any]]:
        """Find all functions that call a given function."""
        callers = []
        
        for addr, func in self.binary_context.function_context_dict.items():
            if hasattr(func, 'callees') and target_addr in func.callees:
                callers.append({
                    "address": addr,
                    "name": func.name
                })
                
        return callers
    
    def generate_summary_report(self) -> Dict[str, Any]:
        """
        Generate a comprehensive summary report of the binary.
        
        Returns:
            Dictionary with summary information
        """
        summary = self.get_basic_stats()
        
        # Add additional analyses
        summary["imported_libraries"] = self.get_imported_libraries()
        summary["entry_points"] = self.identify_entry_points()
        summary["crypto_functions"] = self.find_crypto_functions()
        summary["network_functions"] = self.find_network_functions()
        summary["obfuscation_analysis"] = self.detect_obfuscation()
        summary["interesting_strings"] = self.get_interesting_strings(20)
        
        # Calculate complexity distribution
        complexities = []
        for addr, func in self.binary_context.function_context_dict.items():
            complexities.append(self._calculate_function_complexity(func))
            
        if complexities:
            summary["complexity_stats"] = {
                "min": min(complexities),
                "max": max(complexities),
                "avg": sum(complexities) / len(complexities),
                "high_complexity_count": sum(1 for c in complexities if c > 10)
            }
        else:
            summary["complexity_stats"] = {}
        
        return summary
