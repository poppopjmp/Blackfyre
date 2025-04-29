import yara
import os
import re
from typing import List, Dict, Union, Set
from blackfyre.datatypes.contexts.binarycontext import BinaryContext

class YaraRuleGenerator:
    def __init__(self, binary_context: BinaryContext):
        """Initialize the YARA rule generator
        
        Args:
            binary_context: The BinaryContext to generate rules from
        """
        self.binary_context = binary_context
        
    def _clean_name(self, name: str) -> str:
        """Clean a name for use in a YARA rule name
        
        Args:
            name: The name to clean
        
        Returns:
            A cleaned name suitable for a YARA rule
        """
        # Replace invalid characters with underscores
        cleaned = re.sub(r'[^a-zA-Z0-9_]', '_', name)
        
        # Ensure it starts with a letter
        if not cleaned[0].isalpha():
            cleaned = 'rule_' + cleaned
            
        return cleaned
    
    def _bytes_to_hex_string(self, data: bytes) -> str:
        """Convert bytes to a YARA hex string
        
        Args:
            data: The bytes to convert
            
        Returns:
            A YARA-compatible hex string
        """
        return ' '.join(f"{b:02x}" for b in data)
    
    def generate_string_rules(self, min_length: int = 8, max_rules: int = 50) -> str:
        """Generate YARA rules for interesting strings in the binary
        
        Args:
            min_length: Minimum string length to include
            max_rules: Maximum number of rules to generate
            
        Returns:
            YARA rules as a string
        """
        rules = []
        
        # Sort strings by length (longest first)
        interesting_strings = {
            addr: s for addr, s in self.binary_context.string_refs.items() 
            if len(s) >= min_length and not s.isspace() and re.search(r'[a-zA-Z]', s)
        }
        
        sorted_strings = sorted(
            interesting_strings.items(), 
            key=lambda x: len(x[1]), 
            reverse=True
        )[:max_rules]
        
        # Generate rules
        for addr, string_val in sorted_strings:
            # Skip very common strings
            if string_val.lower() in ('error', 'warning', 'success', 'failed'):
                continue
                
            rule_name = f"string_{self._clean_name(string_val[:20])}_{addr:x}"
            escaped_string = string_val.replace('"', '\\"').replace('\\', '\\\\')
            
            rule = f'''
rule {rule_name} {{
    meta:
        description = "String found in {self.binary_context.name}"
        address = "0x{addr:x}"
    strings:
        $str = "{escaped_string}" ascii wide
    condition:
        $str
}}
'''
            rules.append(rule)
        
        return '\n'.join(rules)
    
    def generate_function_rules(self, min_instructions: int = 10, max_rules: int = 20) -> str:
        """Generate YARA rules for function patterns
        
        Args:
            min_instructions: Minimum number of instructions for a function to be included
            max_rules: Maximum number of rules to generate
            
        Returns:
            YARA rules as a string
        """
        rules = []
        
        # Sort functions by number of instructions (most complex first)
        functions = sorted(
            self.binary_context.function_context_dict.values(),
            key=lambda f: f.total_instructions,
            reverse=True
        )
        
        candidate_functions = [f for f in functions if f.total_instructions >= min_instructions 
                              and not f.is_thunk][:max_rules]
        
        # Generate rules
        for func in candidate_functions:
            # Get basic block bytes
            func_bytes = b''
            bb_bytestrings = []
            
            # In a real implementation, we would extract actual bytes here
            # For this example, we'll create a rule structure but with placeholder patterns
            
            rule_name = f"func_{self._clean_name(func.name)}_{func.start_address:x}"
            
            # Create basic rule structure
            rule = f'''
rule {rule_name} {{
    meta:
        description = "Function pattern for {func.name} in {self.binary_context.name}"
        address = "0x{func.start_address:x}"
        size = {func.end_address - func.start_address}
        instructions = {func.total_instructions}
    strings:
        $seq1 = {{
            // Function prologue pattern would go here
            // In a real implementation, we would extract and include actual bytes
            ?? ?? ?? ?? // Placeholder for actual function bytes
        }}
        
        $seq2 = {{
            // Another distinctive sequence from the function
            // In a real implementation, we would extract and include actual bytes
            ?? ?? ?? ?? // Placeholder for actual function bytes
        }}
    condition:
        any of them
}}
'''
            rules.append(rule)
        
        return '\n'.join(rules)
    
    def generate_import_rules(self) -> str:
        """Generate YARA rules based on import patterns
        
        Returns:
            YARA rules as a string
        """
        # Group imports by library
        libraries = {}
        for import_sym in self.binary_context.import_symbols:
            if import_sym.library_name not in libraries:
                libraries[import_sym.library_name] = []
            libraries[import_sym.library_name].append(import_sym.name)
        
        rules = []
        
        # Generate a rule for each library with significant imports
        for lib_name, imports in libraries.items():
            if len(imports) < 3:  # Skip libraries with few imports
                continue
                
            rule_name = f"imports_{self._clean_name(lib_name)}"
            
            # Create strings section
            strings_section = []
            for i, imp in enumerate(imports[:20]):  # Limit to 20 imports per rule
                strings_section.append(f'        ${i} = "{imp}" ascii wide')
            
            # Create condition
            threshold = min(3, len(imports))
            
            rule = f'''
rule {rule_name} {{
    meta:
        description = "Import pattern for {lib_name} in {self.binary_context.name}"
        import_count = {len(imports)}
    strings:
{chr(10).join(strings_section)}
    condition:
        {threshold} of them
}}
'''
            rules.append(rule)
        
        return '\n'.join(rules)
    
    def generate_all_rules(self, output_file: str = None) -> str:
        """Generate all types of YARA rules
        
        Args:
            output_file: Optional path to write rules to
            
        Returns:
            YARA rules as a string
        """
        rules = []
        
        # Add header
        rules.append(f'''
/*
 * YARA rules generated by Blackfyre
 * Binary: {self.binary_context.name}
 * SHA-256: {self.binary_context.sha256_hash}
 * Architecture: {self.binary_context.proc_type}
 * File Type: {self.binary_context.file_type}
 */
''')
        
        # Generate each type of rule
        rules.append(self.generate_string_rules())
        rules.append(self.generate_function_rules())
        rules.append(self.generate_import_rules())
        
        # Combine rules
        rule_str = '\n'.join(rules)
        
        # Write to file if requested
        if output_file:
            with open(output_file, 'w') as f:
                f.write(rule_str)
            print(f"YARA rules written to {output_file}")
        
        return rule_str
