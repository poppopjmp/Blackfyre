"""Advanced LLM integration for binary analysis"""

import os
import json
import time
import logging
from typing import Dict, List, Tuple, Optional, Any, Union
from blackfyre.ml.llm_integration import LLMConfig, LLMProcessor
from blackfyre.ml.prompt_templates import PromptTemplateManager
from blackfyre.datatypes.contexts.binarycontext import BinaryContext
from blackfyre.datatypes.contexts.functioncontext import FunctionContext

class AdvancedLLMAnalyzer:
    """Advanced LLM integration for binary analysis with enhanced capabilities"""
    
    def __init__(
        self, 
        binary_context: BinaryContext,
        llm_config: Optional[LLMConfig] = None,
        template_config: Optional[str] = None,
        cache_dir: Optional[str] = None
    ):
        """Initialize the advanced LLM analyzer
        
        Args:
            binary_context: The BinaryContext to analyze
            llm_config: Configuration for the LLM (optional)
            template_config: Path to prompt template config file (optional)
            cache_dir: Directory to cache results (optional)
        """
        self.binary_context = binary_context
        
        # Initialize LLM config if not provided
        if llm_config is None:
            # Try to load API key from environment
            api_key = os.environ.get("OPENAI_API_KEY")
            if api_key:
                self.llm_config = LLMConfig(provider="openai", model="gpt-3.5-turbo", api_key=api_key)
            else:
                raise ValueError("No LLM configuration provided and no API key found in environment")
        else:
            self.llm_config = llm_config
            
        # Initialize LLM processor
        self.llm_processor = LLMProcessor(self.llm_config)
        
        # Initialize template manager
        self.template_manager = PromptTemplateManager(config_path=template_config)
        
        # Setup caching
        self.cache_dir = cache_dir
        if cache_dir:
            os.makedirs(cache_dir, exist_ok=True)
            
        self.logger = logging.getLogger(__name__)
        
        # Analysis trackers
        self.analyzed_functions = set()
        self.failed_analyses = set()
    
    def _get_cache_path(self, analysis_type: str, function_addr: Optional[int] = None) -> Optional[str]:
        """Get the cache file path for an analysis
        
        Args:
            analysis_type: Type of analysis (e.g., 'function', 'binary', 'vulnerability')
            function_addr: Function address (for function-specific analyses)
            
        Returns:
            Cache file path or None if caching is disabled
        """
        if not self.cache_dir:
            return None
            
        binary_hash = self.binary_context.sha256_hash[:16]  # Use first 16 chars of hash
        
        if function_addr is not None:
            return os.path.join(
                self.cache_dir, 
                f"{binary_hash}_{analysis_type}_{function_addr:x}.json"
            )
        else:
            return os.path.join(
                self.cache_dir, 
                f"{binary_hash}_{analysis_type}.json"
            )
    
    def _load_from_cache(self, cache_path: str) -> Optional[Dict]:
        """Load analysis results from cache
        
        Args:
            cache_path: Path to cache file
            
        Returns:
            Cached results or None if cache miss
        """
        if not cache_path or not os.path.exists(cache_path):
            return None
            
        try:
            with open(cache_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            self.logger.warning(f"Failed to load cache: {e}")
            return None
    
    def _save_to_cache(self, cache_path: str, data: Dict) -> bool:
        """Save analysis results to cache
        
        Args:
            cache_path: Path to cache file
            data: Analysis data to cache
            
        Returns:
            True if successfully cached
        """
        if not cache_path:
            return False
            
        try:
            with open(cache_path, 'w') as f:
                json.dump(data, f, indent=2)
            return True
        except Exception as e:
            self.logger.warning(f"Failed to save to cache: {e}")
            return False
    
    def analyze_function(
        self, 
        function_addr: int, 
        analysis_type: str = "function_analysis",
        template_params: Optional[Dict[str, str]] = None,
        force_refresh: bool = False
    ) -> Dict[str, Any]:
        """Analyze a function using an LLM
        
        Args:
            function_addr: Address of function to analyze
            analysis_type: Type of analysis to perform (template name)
            template_params: Additional parameters for the template
            force_refresh: Whether to force a refresh of cached results
            
        Returns:
            Analysis results
        """
        # Validate function address
        if function_addr not in self.binary_context.function_context_dict:
            raise ValueError(f"Function not found at address 0x{function_addr:x}")
            
        function = self.binary_context.function_context_dict[function_addr]
        
        # Check cache first
        cache_path = self._get_cache_path(analysis_type, function_addr)
        if not force_refresh and cache_path:
            cached_result = self._load_from_cache(cache_path)
            if cached_result:
                return cached_result
        
        # Format function for analysis
        function_text = self._format_function(function)
        
        # Prepare template parameters
        params = {
            "function_text": function_text,
            "binary_name": self.binary_context.name,
            "architecture": str(self.binary_context.proc_type),
        }
        
        # Add any additional template parameters
        if template_params:
            params.update(template_params)
            
        # Get prompt template
        try:
            template = self.template_manager.get_template(analysis_type)
        except ValueError:
            # Fall back to function_analysis template
            analysis_type = "function_analysis"
            template = self.template_manager.get_template(analysis_type)
        
        # Format the prompt
        system_prompt = template["system_prompt"]
        user_prompt = template["user_prompt"].format(**params)
        
        # Call the LLM
        try:
            analysis = self.llm_processor.call_llm_api(user_prompt, system_prompt)
            
            # Create result object
            result = {
                "function_name": function.name,
                "function_address": function_addr,
                "analysis_type": analysis_type,
                "analysis": analysis,
                "timestamp": time.time()
            }
            
            # Cache the result
            if cache_path:
                self._save_to_cache(cache_path, result)
                
            # Track this function as analyzed
            self.analyzed_functions.add(function_addr)
                
            return result
            
        except Exception as e:
            self.logger.error(f"Error analyzing function at 0x{function_addr:x}: {e}")
            self.failed_analyses.add(function_addr)
            
            return {
                "function_name": function.name,
                "function_address": function_addr,
                "analysis_type": analysis_type,
                "error": str(e),
                "timestamp": time.time()
            }
    
    def _format_function(self, function: FunctionContext) -> str:
        """Format a function for LLM analysis
        
        Args:
            function: The function to format
            
        Returns:
            Formatted function string
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
    
    def batch_analyze_functions(
        self,
        function_addrs: List[int],
        analysis_type: str = "function_analysis",
        max_concurrent: int = 1,
        template_params: Optional[Dict[str, str]] = None,
        force_refresh: bool = False,
        progress_callback: Optional[callable] = None
    ) -> Dict[int, Dict[str, Any]]:
        """Analyze multiple functions in batch
        
        Args:
            function_addrs: List of function addresses to analyze
            analysis_type: Type of analysis to perform (template name)
            max_concurrent: Maximum number of concurrent requests
            template_params: Additional parameters for the template
            force_refresh: Whether to force a refresh of cached results
            progress_callback: Callback function to report progress
            
        Returns:
            Dictionary mapping function addresses to analysis results
        """
        results = {}
        total = len(function_addrs)
        
        # Process functions in batches
        for i, addr in enumerate(function_addrs):
            try:
                # Analyze function
                result = self.analyze_function(
                    addr, 
                    analysis_type=analysis_type,
                    template_params=template_params,
                    force_refresh=force_refresh
                )
                
                results[addr] = result
                
                # Report progress
                if progress_callback:
                    progress_callback(i + 1, total, result)
                    
                # Sleep between requests if needed
                if i < total - 1 and max_concurrent == 1:
                    time.sleep(0.5)  # Avoid rate limiting
                    
            except Exception as e:
                self.logger.error(f"Error batch analyzing function at 0x{addr:x}: {e}")
                # Continue with the next function
        
        return results
    
    def analyze_binary_overview(
        self,
        template_params: Optional[Dict[str, str]] = None,
        force_refresh: bool = False
    ) -> Dict[str, Any]:
        """Generate a high-level analysis of the entire binary
        
        Args:
            template_params: Additional parameters for the template
            force_refresh: Whether to force a refresh of cached results
            
        Returns:
            Binary analysis results
        """
        # Check cache first
        cache_path = self._get_cache_path("binary_summary")
        if not force_refresh and cache_path:
            cached_result = self._load_from_cache(cache_path)
            if cached_result:
                return cached_result
        
        # Prepare binary summary data
        binary_info = {
            "name": self.binary_context.name,
            "architecture": str(self.binary_context.proc_type),
            "function_count": len(self.binary_context.function_context_dict),
            "import_count": len(self.binary_context.import_symbols),
            "export_count": len(self.binary_context.export_symbols),
            "string_count": len(self.binary_context.string_refs),
        }
        
        # Format imports, exports, and strings
        import_list = [f"{imp.name} (from {imp.library_name})" 
                      for imp in self.binary_context.import_symbols[:20]]  # Limit to 20
        export_list = [exp.name for exp in self.binary_context.export_symbols[:20]]  # Limit to 20
        
        # Get interesting strings
        interesting_strings = []
        for addr, string in self.binary_context.string_refs.items():
            if len(string) > 5 and len(string) < 100:  # Filter out very short/long strings
                interesting_strings.append(string)
        interesting_strings = interesting_strings[:30]  # Limit to 30
        
        # Format lists for the prompt
        imports_text = "\n".join([f"- {imp}" for imp in import_list])
        exports_text = "\n".join([f"- {exp}" for exp in export_list])
        strings_text = "\n".join([f"- \"{s}\"" for s in interesting_strings])
        
        # Prepare template parameters
        params = {
            "binary_name": binary_info["name"],
            "architecture": binary_info["architecture"],
            "function_count": binary_info["function_count"],
            "import_count": binary_info["import_count"],
            "export_count": binary_info["export_count"],
            "string_count": binary_info["string_count"],
            "imports": imports_text,
            "exports": exports_text,
            "strings": strings_text
        }
        
        # Add any additional template parameters
        if template_params:
            params.update(template_params)
        
        # Get prompt template
        try:
            template = self.template_manager.get_template("binary_summary")
        except ValueError:
            raise ValueError("binary_summary template not found")
        
        # Format the prompt
        system_prompt = template["system_prompt"]
        user_prompt = template["user_prompt"].format(**params)
        
        # Call the LLM
        try:
            analysis = self.llm_processor.call_llm_api(user_prompt, system_prompt)
            
            # Create result object
            result = {
                "binary_name": self.binary_context.name,
                "analysis": analysis,
                "timestamp": time.time(),
                "metadata": binary_info
            }
            
            # Cache the result
            if cache_path:
                self._save_to_cache(cache_path, result)
                
            return result
            
        except Exception as e:
            self.logger.error(f"Error generating binary overview: {e}")
            
            return {
                "binary_name": self.binary_context.name,
                "error": str(e),
                "timestamp": time.time()
            }
