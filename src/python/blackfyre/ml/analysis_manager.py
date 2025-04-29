"""Manage complex analysis tasks with LLMs"""

import os
import json
import time
from typing import Dict, List, Tuple, Optional, Any, Union
from tqdm import tqdm
import logging
from datetime import datetime
from blackfyre.datatypes.contexts.binarycontext import BinaryContext
from blackfyre.ml.advanced_llm import AdvancedLLMAnalyzer
from blackfyre.ml.llm_similarity import LLMFunctionEmbedder, SemanticFunctionMatcher

class LLMAnalysisManager:
    """Manage and track complex analyses with LLMs"""
    
    def __init__(
        self,
        binary_context: BinaryContext,
        output_dir: str,
        llm_analyzer: Optional[AdvancedLLMAnalyzer] = None
    ):
        """Initialize the analysis manager
        
        Args:
            binary_context: The BinaryContext to analyze
            output_dir: Directory to store results
            llm_analyzer: AdvancedLLMAnalyzer instance (optional)
        """
        self.binary_context = binary_context
        self.output_dir = output_dir
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # Create cache directory
        self.cache_dir = os.path.join(output_dir, "cache")
        os.makedirs(self.cache_dir, exist_ok=True)
        
        # Create results directory
        self.results_dir = os.path.join(output_dir, "results")
        os.makedirs(self.results_dir, exist_ok=True)
        
        # Create LLM analyzer if not provided
        if llm_analyzer is None:
            self.llm_analyzer = AdvancedLLMAnalyzer(
                binary_context, 
                cache_dir=self.cache_dir
            )
        else:
            self.llm_analyzer = llm_analyzer
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
        log_file = os.path.join(output_dir, "analysis.log")
        handler = logging.FileHandler(log_file)
        handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
        
        # Analysis tracking
        self.analysis_status = {
            "binary_name": binary_context.name,
            "binary_hash": binary_context.sha256_hash,
            "start_time": None,
            "end_time": None,
            "completed_analyses": 0,
            "failed_analyses": 0,
            "total_analyses": 0
        }
    
    def run_comprehensive_analysis(
        self,
        max_functions: int = 0,
        analysis_types: List[str] = ["function_analysis"],
        include_similarity: bool = True
    ) -> Dict[str, Any]:
        """Run a comprehensive analysis of the binary
        
        Args:
            max_functions: Maximum functions to analyze (0 for all)
            analysis_types: List of analysis types to perform
            include_similarity: Whether to perform similarity analysis
            
        Returns:
            Analysis summary
        """
        # Record start time
        self.analysis_status["start_time"] = time.time()
        self.logger.info(f"Starting comprehensive analysis of {self.binary_context.name}")
        
        # 1. Generate binary overview
        self.logger.info("Generating binary overview")
        binary_overview = self.llm_analyzer.analyze_binary_overview()
        
        # Save overview
        overview_path = os.path.join(self.results_dir, "binary_overview.md")
        with open(overview_path, 'w') as f:
            f.write(f"# Binary Overview: {self.binary_context.name}\n\n")
            f.write(binary_overview["analysis"])
            
        # 2. Select functions to analyze
        functions_to_analyze = self._select_functions_for_analysis(max_functions)
        self.analysis_status["total_analyses"] = len(functions_to_analyze) * len(analysis_types)
        
        self.logger.info(f"Selected {len(functions_to_analyze)} functions for analysis")
        
        # 3. Analyze each function with each analysis type
        for analysis_type in analysis_types:
            self.logger.info(f"Starting analysis type: {analysis_type}")
            
            # Create output directory for this analysis type
            type_dir = os.path.join(self.results_dir, analysis_type)
            os.makedirs(type_dir, exist_ok=True)
            
            # Create progress bar
            with tqdm(total=len(functions_to_analyze), desc=f"Analyzing with {analysis_type}") as pbar:
                # Define progress callback
                def update_progress(current, total, result):
                    pbar.update(1)
                    if "error" in result:
                        self.analysis_status["failed_analyses"] += 1
                        self.logger.warning(f"Analysis failed for function at 0x{result['function_address']:x}")
                    else:
                        self.analysis_status["completed_analyses"] += 1
                        
                        # Save individual result
                        func_name = result["function_name"]
                        addr = result["function_address"]
                        func_file = os.path.join(type_dir, f"{addr:x}_{func_name}.md")
                        
                        with open(func_file, 'w') as f:
                            f.write(f"# {func_name} (0x{addr:x})\n\n")
                            f.write(result["analysis"])
                
                # Batch analyze functions
                self.llm_analyzer.batch_analyze_functions(
                    functions_to_analyze,
                    analysis_type=analysis_type,
                    progress_callback=update_progress
                )
        
        # 4. Perform similarity analysis if requested
        if include_similarity:
            self.logger.info("Starting similarity analysis")
            
            # Create similarity matcher
            matcher = SemanticFunctionMatcher(
                self.binary_context,
                cache_dir=os.path.join(self.cache_dir, "embeddings")
            )
            
            # Compute embeddings
            with tqdm(total=len(functions_to_analyze), desc="Computing embeddings") as pbar:
                def update_embedding_progress(current, total, name):
                    pbar.update(1)
                    pbar.set_description(f"Computing embedding for {name}")
                    
                matcher.compute_embeddings(
                    max_functions=len(functions_to_analyze),
                    progress_callback=update_embedding_progress
                )
            
            # Find clusters of similar functions
            clusters = matcher.cluster_similar_functions(threshold=0.85)
            
            # Save clusters
            clusters_path = os.path.join(self.results_dir, "function_clusters.json")
            with open(clusters_path, 'w') as f:
                json.dump(clusters, f, indent=2)
                
            # Generate cluster report
            clusters_report = os.path.join(self.results_dir, "function_clusters.md")
            with open(clusters_report, 'w') as f:
                f.write("# Function Similarity Clusters\n\n")
                f.write(f"Binary: {self.binary_context.name}\n\n")
                
                for i, cluster in enumerate(clusters):
                    f.write(f"## Cluster {i+1} ({cluster['size']} functions)\n\n")
                    
                    for func in cluster["functions"]:
                        f.write(f"- {func['name']} (0x{func['address']:x}, {func['size']} bytes)\n")
                    
                    f.write("\n")
            
            self.logger.info(f"Found {len(clusters)} function clusters")
        
        # 5. Generate final report
        self.analysis_status["end_time"] = time.time()
        duration = self.analysis_status["end_time"] - self.analysis_status["start_time"]
        
        # Save analysis status
        status_path = os.path.join(self.results_dir, "analysis_status.json")
        with open(status_path, 'w') as f:
            json.dump(self.analysis_status, f, indent=2)
        
        # Generate summary report
        summary_path = os.path.join(self.results_dir, "analysis_summary.md")
        with open(summary_path, 'w') as f:
            f.write(f"# Analysis Summary: {self.binary_context.name}\n\n")
            f.write(f"- **Date:** {datetime.fromtimestamp(self.analysis_status['start_time']).strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"- **Duration:** {duration:.2f} seconds\n")
            f.write(f"- **Functions Analyzed:** {len(functions_to_analyze)}\n")
            f.write(f"- **Analysis Types:** {', '.join(analysis_types)}\n")
            f.write(f"- **Completed Analyses:** {self.analysis_status['completed_analyses']}\n")
            f.write(f"- **Failed Analyses:** {self.analysis_status['failed_analyses']}\n\n")
            
            f.write("## Key Findings\n\n")
            f.write("See binary_overview.md for a general analysis of the binary.\n\n")
            
            if include_similarity:
                f.write(f"Found {len(clusters)} clusters of similar functions. See function_clusters.md for details.\n\n")
            
            f.write("## Analysis Types\n\n")
            for analysis_type in analysis_types:
                f.write(f"- {analysis_type}\n")
        
        self.logger.info(f"Analysis completed in {duration:.2f} seconds")
        
        return {
            "status": self.analysis_status,
            "overview_path": overview_path,
            "summary_path": summary_path,
            "results_dir": self.results_dir
        }
    
    def _select_functions_for_analysis(self, max_functions: int = 0) -> List[int]:
        """Select the most important functions for analysis
        
        Args:
            max_functions: Maximum functions to select (0 for all)
            
        Returns:
            List of function addresses
        """
        # Start with all functions
        functions = []
        
        # Filter out thunks (import wrappers)
        for addr, func in self.binary_context.function_context_dict.items():
            if not func.is_thunk:
                functions.append((addr, func))
        
        # If max_functions is 0 or greater than total, analyze all functions
        if max_functions <= 0 or max_functions >= len(functions):
            return [addr for addr, _ in functions]
        
        # Otherwise, select functions based on importance
        
        # 1. First, include entry points and "main" functions
        selected = set()
        for addr, func in functions:
            func_name = func.name.lower()
            if func_name == "main" or "_main" in func_name or "entry" in func_name:
                selected.add(addr)
                
        # 2. Then, include functions with the most callees (complex functions)
        complex_functions = sorted(
            [(addr, len(func.callees)) for addr, func in functions],
            key=lambda x: x[1],
            reverse=True
        )
        
        for addr, _ in complex_functions:
            if addr not in selected:
                selected.add(addr)
                if len(selected) >= max_functions:
                    break
        
        return list(selected)
