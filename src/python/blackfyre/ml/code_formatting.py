"""Utilities for formatting binary code for LLM processing"""

import re
from typing import Dict, List, Set, Tuple, Optional, Union, Any
from blackfyre.datatypes.contexts.binarycontext import BinaryContext
from blackfyre.datatypes.contexts.functioncontext import FunctionContext

class CodeFormatter:
    """Format binary code for LLM analysis"""
    
    @staticmethod
    def format_instruction(instruction: Any) -> str:
        """Format an instruction for display
        
        Args:
            instruction: Instruction object
            
        Returns:
            Formatted instruction string
        """
        if hasattr(instruction, "mnemonic") and hasattr(instruction, "operands"):
            return f"{instruction.mnemonic} {instruction.operands}"
        elif hasattr(instruction, "mnemonic") and hasattr(instruction, "args"):
            return f"{instruction.mnemonic} {', '.join(str(a) for a in instruction.args)}"
        else:
            # Fallback formatting
            return str(instruction)
    
    @staticmethod
    def format_basic_block(block: Any, indent: int = 2) -> str:
        """Format a basic block for display
        
        Args:
            block: BasicBlockContext object
            indent: Number of spaces for indentation
            
        Returns:
            Formatted basic block string
        """
        indent_str = " " * indent
        result = f"Block 0x{block.start_address:x} - 0x{block.end_address:x}:\n"
        
        for instruction in block.instruction_contexts:
            result += f"{indent_str}{CodeFormatter.format_instruction(instruction)}\n"
            
        return result
    
    @staticmethod
    def format_function_summary(function: FunctionContext, binary_context: BinaryContext) -> str:
        """Create a concise function summary
        
        Args:
            function: Function to summarize
            binary_context: Binary context
            
        Returns:
            Formatted function summary
        """
        summary = f"Function {function.name} (0x{function.start_address:x} - 0x{function.end_address:x})\n"
        summary += f"Size: {function.end_address - function.start_address} bytes\n"
        
        # Add basic stats
        summary += f"Basic blocks: {len(function.basic_block_contexts)}\n"
        summary += f"Instructions: {function.total_instructions}\n"
        
        # Add callee information if available
        if hasattr(function, "callees") and function.callees:
            summary += f"Calls {len(function.callees)} functions:\n"
            for callee_addr in function.callees[:5]:  # Limit to first 5
                if callee_addr in binary_context.function_context_dict:
                    callee = binary_context.function_context_dict[callee_addr]
                    summary += f"  - {callee.name} (0x{callee_addr:x})\n"
                    
            if len(function.callees) > 5:
                summary += f"  - ... and {len(function.callees) - 5} more\n"
        
        return summary
    
    @staticmethod
    def decompilation_to_pseudocode(decompiled_code: str) -> str:
        """Convert decompiled C code to cleaner pseudocode
        
        Args:
            decompiled_code: Decompiled C code
            
        Returns:
            Simplified pseudocode representation
        """
        # This is a simplified version - in a real implementation, 
        # we would do more sophisticated processing
        
        # Remove type declarations
        code = re.sub(r'\b(int|char|void|long|double|float|unsigned|struct|union)\s+', '', decompiled_code)
        
        # Remove pointer asterisks
        code = code.replace('*', '')
        
        # Remove semicolons
        code = code.replace(';', '')
        
        # Clean up multiple spaces and newlines
        code = re.sub(r'\s+', ' ', code)
        code = re.sub(r'\s*\n\s*', '\n', code)
        
        return code


class PromptTemplates:
    """Templates for different LLM analysis tasks"""
    
    @staticmethod
    def function_analysis() -> Dict[str, str]:
        """Get templates for function analysis
        
        Returns:
            Dictionary with system and user prompt templates
        """
        system_prompt = """
        You are a binary code analysis expert. Your task is to analyze and explain the 
        provided function. Focus on:
        1. What the function does (its purpose)
        2. Key algorithms or operations performed
        3. Security implications (if any)
        4. Return values and parameters
        5. Interesting observations
        
        Provide a clear, concise explanation in a professional tone.
        """
        
        user_prompt = """
        Please analyze this function from a binary and explain what it does:
        
        {function_text}
        
        Binary name: {binary_name}
        Architecture: {architecture}
        
        Provide your analysis in the following format:
        
        ## Purpose
        [Brief description of what this function does]
        
        ## Parameters and Returns
        [Description of inputs and outputs]
        
        ## Key Operations
        [List of key operations or algorithms]
        
        ## Security Considerations
        [Any security implications]
        
        ## Additional Notes
        [Any other interesting observations]
        """
        
        return {
            "system_prompt": system_prompt,
            "user_prompt": user_prompt
        }
    
    @staticmethod
    def vulnerability_assessment() -> Dict[str, str]:
        """Get templates for vulnerability assessment
        
        Returns:
            Dictionary with system and user prompt templates
        """
        system_prompt = """
        You are an expert in security vulnerability assessment. Your task is to analyze
        the provided function and identify any potential security vulnerabilities. 
        
        Focus on:
        1. Buffer overflows
        2. Format string vulnerabilities
        3. Integer overflows/underflows
        4. Use-after-free
        5. Race conditions
        6. Command/SQL injection
        7. Other memory safety issues
        
        Be specific and cite evidence from the code. If you're uncertain, indicate your
        confidence level.
        """
        
        user_prompt = """
        Please analyze this function for potential security vulnerabilities:
        
        {function_text}
        
        Binary name: {binary_name}
        Architecture: {architecture}
        
        Provide your assessment in the following format:
        
        ## Overview
        [Brief description of the function]
        
        ## Identified Vulnerabilities
        [List each vulnerability with evidence]
        
        ## Risk Assessment
        [High/Medium/Low risk assessment with explanation]
        
        ## Recommendations
        [How to address these vulnerabilities]
        """
        
        return {
            "system_prompt": system_prompt,
            "user_prompt": user_prompt
        }
    
    @staticmethod
    def algorithm_identification() -> Dict[str, str]:
        """Get templates for algorithm identification
        
        Returns:
            Dictionary with system and user prompt templates
        """
        system_prompt = """
        You are an algorithm identification specialist. Your task is to identify
        known algorithms in the provided binary function. Examples include:
        1. Cryptographic algorithms (AES, RSA, SHA, etc.)
        2. Compression algorithms (zlib, LZMA, etc.)
        3. Common data structure operations (tree traversal, graph algorithms)
        4. Sorting and searching algorithms
        5. String manipulation algorithms
        
        Be precise and explain your reasoning.
        """
        
        user_prompt = """
        Please identify any known algorithms implemented in this function:
        
        {function_text}
        
        Binary name: {binary_name}
        Architecture: {architecture}
        
        Provide your analysis in the following format:
        
        ## Identified Algorithm(s)
        [Name and variant of algorithm(s) identified]
        
        ## Evidence
        [Why you believe this is the algorithm]
        
        ## Confidence
        [High/Medium/Low with explanation]
        
        ## Algorithm Description
        [Brief description of what the algorithm does]
        """
        
        return {
            "system_prompt": system_prompt,
            "user_prompt": user_prompt
        }
