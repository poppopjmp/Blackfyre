"""Integration with Large Language Models for binary code analysis"""

import os
import json
import time
import logging
import requests
from typing import Dict, List, Any, Optional, Union
from blackfyre.datatypes.contexts.binarycontext import BinaryContext
from blackfyre.datatypes.contexts.functioncontext import FunctionContext

class LLMConfig:
    """Configuration for LLM integration"""
    
    def __init__(self, 
                 provider: str = "openai", 
                 model: str = "gpt-4",
                 api_key: Optional[str] = None,
                 api_endpoint: Optional[str] = None):
        """Initialize LLM configuration
        
        Args:
            provider: LLM provider name ('openai', 'anthropic', 'azure', etc.)
            model: Model name to use
            api_key: API key (if None, will look for environment variable)
            api_endpoint: Custom API endpoint (if None, will use default)
        """
        self.provider = provider.lower()
        self.model = model
        
        # Set API key from parameters or environment
        if api_key is None:
            if provider == "openai":
                api_key = os.environ.get("OPENAI_API_KEY")
            elif provider == "anthropic":
                api_key = os.environ.get("ANTHROPIC_API_KEY")
            elif provider == "azure":
                api_key = os.environ.get("AZURE_OPENAI_KEY")
        
        self.api_key = api_key
        
        # Set API endpoint
        if api_endpoint is None:
            if provider == "openai":
                api_endpoint = "https://api.openai.com/v1/chat/completions"
            elif provider == "anthropic":
                api_endpoint = "https://api.anthropic.com/v1/messages"
            elif provider == "azure":
                # Azure requires a custom endpoint set by user
                raise ValueError("Azure OpenAI requires a custom endpoint")
        
        self.api_endpoint = api_endpoint
        
        # Set default parameters
        self.params = {
            "temperature": 0.2,  # Low temperature for more deterministic outputs
            "max_tokens": 2048,
            "timeout": 60,  # Timeout in seconds
        }
    
    def validate(self) -> bool:
        """Validate the configuration
        
        Returns:
            True if configuration is valid, otherwise raises exception
        """
        if not self.api_key:
            raise ValueError(f"No API key provided for {self.provider}")
        
        if not self.api_endpoint:
            raise ValueError(f"No API endpoint provided for {self.provider}")
        
        return True


class LLMProcessor:
    """Process binary code with Large Language Models"""
    
    def __init__(self, config: LLMConfig):
        """Initialize the LLM processor
        
        Args:
            config: LLM configuration
        """
        self.config = config
        self.config.validate()
        self.logger = logging.getLogger(__name__)
    
    def format_message(self, prompt: str, system_prompt: Optional[str] = None) -> Dict:
        """Format a message for the LLM API based on provider
        
        Args:
            prompt: User prompt text
            system_prompt: Optional system prompt for context
            
        Returns:
            Formatted message dictionary for API request
        """
        if self.config.provider == "openai" or self.config.provider == "azure":
            messages = []
            
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
                
            messages.append({"role": "user", "content": prompt})
            
            return {
                "model": self.config.model,
                "messages": messages,
                "temperature": self.config.params["temperature"],
                "max_tokens": self.config.params["max_tokens"]
            }
            
        elif self.config.provider == "anthropic":
            return {
                "model": self.config.model,
                "system": system_prompt if system_prompt else "",
                "messages": [
                    {"role": "user", "content": prompt}
                ],
                "temperature": self.config.params["temperature"],
                "max_tokens": self.config.params["max_tokens"]
            }
        
        raise ValueError(f"Unsupported provider: {self.config.provider}")
    
    def call_llm_api(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Call the LLM API with a prompt
        
        Args:
            prompt: The prompt to send to the LLM
            system_prompt: Optional system prompt for context
            
        Returns:
            Response from the LLM
        """
        headers = {
            "Content-Type": "application/json"
        }
        
        if self.config.provider == "openai":
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        elif self.config.provider == "anthropic":
            headers["x-api-key"] = self.config.api_key
            headers["anthropic-version"] = "2023-06-01"
        elif self.config.provider == "azure":
            headers["api-key"] = self.config.api_key
        
        # Prepare the request payload
        payload = self.format_message(prompt, system_prompt)
        
        try:
            response = requests.post(
                self.config.api_endpoint,
                headers=headers,
                json=payload,
                timeout=self.config.params["timeout"]
            )
            
            response.raise_for_status()
            response_data = response.json()
            
            # Extract text from response based on provider
            if self.config.provider == "openai" or self.config.provider == "azure":
                return response_data["choices"][0]["message"]["content"]
            elif self.config.provider == "anthropic":
                return response_data["content"][0]["text"]
            
        except requests.RequestException as e:
            self.logger.error(f"API call failed: {e}")
            if hasattr(e, "response") and hasattr(e.response, "text"):
                self.logger.error(f"Response: {e.response.text}")
            raise
        
        return ""


class CodeExplainer:
    """Explain binary code using LLMs"""
    
    def __init__(self, binary_context: BinaryContext, llm_processor: LLMProcessor):
        """Initialize the code explainer
        
        Args:
            binary_context: The BinaryContext to analyze
            llm_processor: LLM processor for analysis
        """
        self.binary_context = binary_context
        self.llm_processor = llm_processor
        
    def format_function_for_prompt(self, function: FunctionContext) -> str:
        """Format a function for inclusion in an LLM prompt
        
        Args:
            function: The function to format
            
        Returns:
            Function formatted as text for LLM analysis
        """
        # Start with function name and location
        formatted = f"Function: {function.name} at address 0x{function.start_address:x}\n\n"
        
        # Add decompiled code if available
        if hasattr(function, "decompiled_code") and function.decompiled_code:
            formatted += "Decompiled code:\n```c\n"
            formatted += function.decompiled_code
            formatted += "\n```\n\n"
        else:
            # If no decompiled code, add assembly
            formatted += "Assembly code:\n```asm\n"
            for bb in function.basic_block_contexts:
                formatted += f"Block 0x{bb.start_address:x}:\n"
                for instr in bb.instruction_contexts:
                    if hasattr(instr, "mnemonic") and hasattr(instr, "operands"):
                        formatted += f"  {instr.mnemonic} {instr.operands}\n"
            formatted += "```\n\n"
        
        # Add function calls
        if hasattr(function, "callees") and function.callees:
            formatted += "Function calls:\n"
            for callee_addr in function.callees:
                if callee_addr in self.binary_context.function_context_dict:
                    callee = self.binary_context.function_context_dict[callee_addr]
                    formatted += f"- 0x{callee_addr:x}: {callee.name}\n"
            formatted += "\n"
        
        # Add string references
        if hasattr(function, "string_refs") and function.string_refs:
            formatted += "String references:\n"
            for addr, string in function.string_refs.items():
                # Truncate long strings
                if len(string) > 100:
                    string = string[:97] + "..."
                formatted += f"- 0x{addr:x}: \"{string}\"\n"
            formatted += "\n"
        
        return formatted
    
    def explain_function(self, function_addr: int) -> Dict[str, Any]:
        """Get an explanation of a function from an LLM
        
        Args:
            function_addr: Address of function to explain
            
        Returns:
            Dictionary containing explanation and metadata
        """
        if function_addr not in self.binary_context.function_context_dict:
            raise ValueError(f"Function not found at address {hex(function_addr)}")
        
        function = self.binary_context.function_context_dict[function_addr]
        
        # Format the function for analysis
        function_text = self.format_function_for_prompt(function)
        
        # Create the prompt
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
        
        prompt = f"""
        Please analyze this function from a binary and explain what it does:
        
        {function_text}
        
        Binary name: {self.binary_context.name}
        Architecture: {self.binary_context.proc_type}
        
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
        
        # Call the LLM
        try:
            explanation = self.llm_processor.call_llm_api(prompt, system_prompt)
            
            return {
                "function_name": function.name,
                "function_address": function_addr,
                "explanation": explanation,
                "binary_name": self.binary_context.name,
                "timestamp": time.time()
            }
        except Exception as e:
            self.logger.error(f"Error explaining function: {e}")
            return {
                "function_name": function.name,
                "function_address": function_addr,
                "explanation": f"Error: {str(e)}",
                "binary_name": self.binary_context.name,
                "timestamp": time.time()
            }
    
    def identify_function_purpose(self, function_addr: int) -> str:
        """Identify the purpose of a function using LLM
        
        Args:
            function_addr: Address of the function to analyze
            
        Returns:
            Brief description of function purpose
        """
        if function_addr not in self.binary_context.function_context_dict:
            raise ValueError(f"Function not found at address {hex(function_addr)}")
        
        function = self.binary_context.function_context_dict[function_addr]
        
        # Format the function for analysis
        function_text = self.format_function_for_prompt(function)
        
        # Create a focused prompt for function purpose
        prompt = f"""
        Examine this function and provide a one-sentence description of its purpose:
        
        {function_text}
        
        Respond with only a single sentence describing what this function does.
        """
        
        # Call the LLM with a simple system prompt
        system_prompt = "You are a binary code analysis expert. Provide brief, accurate responses."
        
        try:
            return self.llm_processor.call_llm_api(prompt, system_prompt)
        except Exception as e:
            self.logger.error(f"Error identifying function purpose: {e}")
            return f"Error: {str(e)}"
