import difflib
from typing import Dict, List, Set, Tuple, Optional
from blackfyre.datatypes.contexts.binarycontext import BinaryContext

class BinaryDiff:
    """Compare two binaries for security-relevant changes"""
    
    def __init__(self, original_bcc: BinaryContext, updated_bcc: BinaryContext):
        """Initialize the binary diff
        
        Args:
            original_bcc: The original/older binary context
            updated_bcc: The updated/newer binary context
        """
        self.original = original_bcc
        self.updated = updated_bcc
        
    def compare_metadata(self) -> Dict:
        """Compare basic metadata between the binaries
        
        Returns:
            Dictionary of metadata differences
        """
        return {
            "name": {
                "original": self.original.name,
                "updated": self.updated.name,
                "changed": self.original.name != self.updated.name
            },
            "sha256_hash": {
                "original": self.original.sha256_hash,
                "updated": self.updated.sha256_hash,
                "changed": self.original.sha256_hash != self.updated.sha256_hash
            },
            "proc_type": {
                "original": str(self.original.proc_type),
                "updated": str(self.updated.proc_type),
                "changed": self.original.proc_type != self.updated.proc_type
            },
            "file_type": {
                "original": str(self.original.file_type),
                "updated": str(self.updated.file_type),
                "changed": self.original.file_type != self.updated.file_type
            },
            "file_size": {
                "original": self.original.file_size,
                "updated": self.updated.file_size,
                "changed": self.original.file_size != self.updated.file_size,
                "diff": self.updated.file_size - self.original.file_size
                if hasattr(self.original, "file_size") and hasattr(self.updated, "file_size")
                else None
            }
        }
    
    def compare_functions(self) -> Dict:
        """Compare functions between binaries
        
        Returns:
            Dictionary with analysis of function changes
        """
        original_funcs = set(self.original.function_context_dict.keys())
        updated_funcs = set(self.updated.function_context_dict.keys())
        
        added_funcs = updated_funcs - original_funcs
        removed_funcs = original_funcs - updated_funcs
        common_funcs = original_funcs.intersection(updated_funcs)
        
        # Analyze common functions for changes
        modified_funcs = []
        for addr in common_funcs:
            orig_func = self.original.function_context_dict[addr]
            updated_func = self.updated.function_context_dict[addr]
            
            # Check if function content has changed
            if orig_func.total_instructions != updated_func.total_instructions:
                modified_funcs.append(addr)
            elif orig_func.name != updated_func.name:
                modified_funcs.append(addr)
            # More thorough checking could be done here with decompiled code comparison
        
        return {
            "added_functions": {
                "count": len(added_funcs),
                "addresses": sorted(list(added_funcs)),
                "names": [self.updated.function_context_dict[addr].name for addr in added_funcs]
            },
            "removed_functions": {
                "count": len(removed_funcs),
                "addresses": sorted(list(removed_funcs)),
                "names": [self.original.function_context_dict[addr].name for addr in removed_funcs]
            },
            "modified_functions": {
                "count": len(modified_funcs),
                "addresses": sorted(modified_funcs),
                "names": [self.updated.function_context_dict[addr].name for addr in modified_funcs]
            },
            "unchanged_functions": {
                "count": len(common_funcs) - len(modified_funcs)
            }
        }
    
    def compare_strings(self) -> Dict:
        """Compare strings between binaries
        
        Returns:
            Dictionary with analysis of string changes
        """
        original_strings = set(self.original.string_refs.items())
        updated_strings = set(self.updated.string_refs.items())
        
        # Convert to sets of (addr, string) for comparison
        orig_str_set = {(addr, s) for addr, s in self.original.string_refs.items()}
        updated_str_set = {(addr, s) for addr, s in self.updated.string_refs.items()}
        
        # Find strings that were added, removed, or moved
        added_strings = [s for s in updated_str_set if s not in orig_str_set]
        removed_strings = [s for s in orig_str_set if s not in updated_str_set]
        
        # Find moved strings (same content, different address)
        orig_str_by_content = {}
        for addr, s in self.original.string_refs.items():
            if s not in orig_str_by_content:
                orig_str_by_content[s] = []
            orig_str_by_content[s].append(addr)
            
        moved_strings = []
        for addr, s in self.updated.string_refs.items():
            if s in orig_str_by_content and addr not in orig_str_by_content[s]:
                moved_strings.append({
                    "string": s,
                    "original_address": orig_str_by_content[s][0],
                    "new_address": addr
                })
        
        return {
            "added_strings": {
                "count": len(added_strings),
                "strings": [(hex(addr), s) for addr, s in added_strings[:20]]  # Limit for readability
            },
            "removed_strings": {
                "count": len(removed_strings),
                "strings": [(hex(addr), s) for addr, s in removed_strings[:20]]
            },
            "moved_strings": {
                "count": len(moved_strings),
                "strings": moved_strings[:20]
            }
        }
    
    def compare_imports(self) -> Dict:
        """Compare imported symbols between binaries
        
        Returns:
            Dictionary with analysis of import changes
        """
        # Create sets of import names for comparison
        orig_imports = {(imp.name, imp.library_name) for imp in self.original.import_symbols}
        updated_imports = {(imp.name, imp.library_name) for imp in self.updated.import_symbols}
        
        added_imports = updated_imports - orig_imports
        removed_imports = orig_imports - updated_imports
        
        return {
            "added_imports": {
                "count": len(added_imports),
                "imports": sorted([(name, lib) for name, lib in added_imports])
            },
            "removed_imports": {
                "count": len(removed_imports),
                "imports": sorted([(name, lib) for name, lib in removed_imports])
            }
        }
    
    def compare_decompiled_code(self, function_addr: int) -> Dict:
        """Compare decompiled code for a specific function
        
        Args:
            function_addr: Address of the function to compare
            
        Returns:
            Dictionary with analysis of code changes
        """
        # Check if function exists in both binaries
        if function_addr not in self.original.function_context_dict or \
           function_addr not in self.updated.function_context_dict:
            return {
                "error": "Function not found in both binaries",
                "function_address": hex(function_addr)
            }
        
        # Get the functions
        orig_func = self.original.function_context_dict[function_addr]
        updated_func = self.updated.function_context_dict[function_addr]
        
        # Get decompiled code
        orig_code = orig_func.decompiled_code if hasattr(orig_func, "decompiled_code") else ""
        updated_code = updated_func.decompiled_code if hasattr(updated_func, "decompiled_code") else ""
        
        # Calculate diff
        diff = list(difflib.unified_diff(
            orig_code.splitlines(),
            updated_code.splitlines(),
            lineterm='',
            fromfile=f"original/{orig_func.name}",
            tofile=f"updated/{updated_func.name}"
        ))
        
        return {
            "function_name": updated_func.name,
            "address": hex(function_addr),
            "original_code": orig_code,
            "updated_code": updated_code,
            "diff": diff
        }
    
    def analyze_security_implications(self) -> Dict:
        """Analyze security implications of changes
        
        Returns:
            Dictionary with security analysis
        """
        security_findings = []
        
        # Check for added security-related functions
        function_diff = self.compare_functions()
        import_diff = self.compare_imports()
        
        # Look for security-relevant imports that were added or removed
        security_imports = {
            "crypto": ["crypt", "aes", "sha", "md5", "ssl", "tls", "encrypt", "decrypt"],
            "memory_safety": ["malloc", "free", "realloc", "memcpy", "strcpy", "strcat"],
            "authentication": ["auth", "login", "password", "cred", "token"],
            "network": ["socket", "connect", "bind", "listen", "http", "ftp", "ssh"]
        }
        
        for category, keywords in security_imports.items():
            # Check added imports
            for name, lib in import_diff["added_imports"]["imports"]:
                for keyword in keywords:
                    if keyword.lower() in name.lower():
                        security_findings.append({
                            "type": "added_import",
                            "category": category,
                            "name": name,
                            "library": lib,
                            "severity": "medium",
                            "description": f"Added import of security-relevant function {name} from {lib}"
                        })
                        break
            
            # Check removed imports
            for name, lib in import_diff["removed_imports"]["imports"]:
                for keyword in keywords:
                    if keyword.lower() in name.lower():
                        security_findings.append({
                            "type": "removed_import",
                            "category": category,
                            "name": name,
                            "library": lib,
                            "severity": "medium",
                            "description": f"Removed import of security-relevant function {name} from {lib}"
                        })
                        break
        
        # Check for interesting strings
        string_diff = self.compare_strings()
        security_string_keywords = [
            "password", "key", "secret", "token", "credentials",
            "vulnerability", "exploit", "backdoor", "debug"
        ]
        
        for addr, string in string_diff["added_strings"]["strings"]:
            for keyword in security_string_keywords:
                if keyword.lower() in string.lower():
                    security_findings.append({
                        "type": "added_string",
                        "address": addr,
                        "string": string,
                        "keyword": keyword,
                        "severity": "low",
                        "description": f"Added string containing '{keyword}': '{string}'"
                    })
                    break
                    
        for addr, string in string_diff["removed_strings"]["strings"]:
            for keyword in security_string_keywords:
                if keyword.lower() in string.lower():
                    security_findings.append({
                        "type": "removed_string",
                        "address": addr,
                        "string": string,
                        "keyword": keyword,
                        "severity": "low",
                        "description": f"Removed string containing '{keyword}': '{string}'"
                    })
                    break
        
        return {
            "findings": security_findings,
            "total_findings": len(security_findings),
            "severity_counts": {
                "high": sum(1 for f in security_findings if f.get("severity") == "high"),
                "medium": sum(1 for f in security_findings if f.get("severity") == "medium"),
                "low": sum(1 for f in security_findings if f.get("severity") == "low")
            }
        }
    
    def generate_report(self, output_file: Optional[str] = None) -> str:
        """Generate a comprehensive diff report
        
        Args:
            output_file: Optional path to write the report to
            
        Returns:
            The report as a string (markdown format)
        """
        metadata_diff = self.compare_metadata()
        function_diff = self.compare_functions()
        string_diff = self.compare_strings()
        import_diff = self.compare_imports()
        security_analysis = self.analyze_security_implications()
        
        # Generate markdown report
        report = f"""# Binary Diff Report

## Metadata
- Original: {metadata_diff['name']['original']} ({metadata_diff['sha256_hash']['original']})
- Updated: {metadata_diff['name']['updated']} ({metadata_diff['sha256_hash']['updated']})
- File size change: {metadata_diff['file_size'].get('diff', 'N/A')} bytes

## Function Analysis
- Added functions: {function_diff['added_functions']['count']}
- Removed functions: {function_diff['removed_functions']['count']}
- Modified functions: {function_diff['modified_functions']['count']}
- Unchanged functions: {function_diff['unchanged_functions']['count']}

### Added Functions (up to 10)
"""
        
        # Show some added functions
        for i, addr in enumerate(function_diff['added_functions']['addresses'][:10]):
            name = self.updated.function_context_dict[addr].name
            report += f"- {name} (0x{addr:x})\n"
            
        report += "\n### Modified Functions (up to 10)\n"
        for i, addr in enumerate(function_diff['modified_functions']['addresses'][:10]):
            name = self.updated.function_context_dict[addr].name
            report += f"- {name} (0x{addr:x})\n"
            
        report += f"""
## String Analysis
- Added strings: {string_diff['added_strings']['count']}
- Removed strings: {string_diff['removed_strings']['count']}
- Moved strings: {string_diff['moved_strings']['count']}

## Import Analysis
- Added imports: {import_diff['added_imports']['count']}
- Removed imports: {import_diff['removed_imports']['count']}

## Security Analysis
- Total security findings: {security_analysis['total_findings']}
- High severity: {security_analysis['severity_counts']['high']}
- Medium severity: {security_analysis['severity_counts']['medium']}
- Low severity: {security_analysis['severity_counts']['low']}

### Security Findings
"""
        
        for i, finding in enumerate(security_analysis['findings']):
            report += f"#### {i+1}. {finding['description']}\n"
            report += f"- Severity: {finding['severity']}\n"
            report += f"- Type: {finding['type']}\n"
            
            if finding['type'] == 'added_import' or finding['type'] == 'removed_import':
                report += f"- Function: {finding['name']}\n"
                report += f"- Library: {finding['library']}\n"
            elif finding['type'] == 'added_string' or finding['type'] == 'removed_string':
                report += f"- Address: {finding['address']}\n"
                report += f"- String: \"{finding['string']}\"\n"
                
            report += "\n"
            
        # Write to file if requested
        if output_file:
            with open(output_file, 'w') as f:
                f.write(report)
            print(f"Diff report written to {output_file}")
        
        return report
