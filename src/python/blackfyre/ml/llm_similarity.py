"""Function similarity detection using LLM-based embeddings"""

import numpy as np
import json
import os
from typing import Dict, List, Tuple, Optional, Any, Union
from scipy.spatial.distance import cosine
from blackfyre.datatypes.contexts.binarycontext import BinaryContext
from blackfyre.ml.llm_integration import LLMConfig, LLMProcessor

class LLMFunctionEmbedder:
    """Generate embeddings for functions using LLMs"""
    
    def __init__(self, llm_config: Optional[LLMConfig] = None, cache_dir: Optional[str] = None):
        """Initialize the function embedder
        
        Args:
            llm_config: Configuration for the LLM (optional)
            cache_dir: Directory to cache embeddings (optional)
        """
        # Initialize LLM config if not provided
        if llm_config is None:
            # Try to load API key from environment
            api_key = os.environ.get("OPENAI_API_KEY")
            if api_key:
                self.llm_config = LLMConfig(provider="openai", model="text-embedding-ada-002", api_key=api_key)
            else:
                raise ValueError("No LLM configuration provided and no API key found in environment")
        else:
            self.llm_config = llm_config
            
        # Initialize LLM processor
        self.llm_processor = LLMProcessor(self.llm_config)
        
        # Setup caching
        self.cache_dir = cache_dir
        if cache_dir:
            os.makedirs(cache_dir, exist_ok=True)
        
        # Track embedded functions
        self.embeddings_cache = {}
    
    def _format_function_for_embedding(self, function_context) -> str:
        """Format a function for embedding generation
        
        Args:
            function_context: The function to format
            
        Returns:
            Formatted function string for embedding
        """
        # For embeddings, we want to focus on the core functionality
        # and remove unnecessary details
        
        # Start with function name
        formatted = f"Function name: {function_context.name}\n\n"
        
        # Add decompiled code if available (preferred for embeddings)
        if hasattr(function_context, "decompiled_code") and function_context.decompiled_code:
            formatted += "Decompiled code:\n"
            formatted += function_context.decompiled_code
        else:
            # Fall back to assembly format for key blocks
            formatted += "Assembly code summary:\n"
            for bb in function_context.basic_block_contexts[:5]:  # Limit to first 5 blocks
                formatted += f"Block at 0x{bb.start_address:x}:\n"
                for instr in bb.instruction_contexts[:10]:  # Limit to first 10 instructions per block
                    if hasattr(instr, "mnemonic") and hasattr(instr, "operands"):
                        formatted += f"{instr.mnemonic} {instr.operands}\n"
        
        # Add function calls (key for understanding function purpose)
        if hasattr(function_context, "callees") and function_context.callees:
            formatted += "\nCalls to: "
            called_funcs = []
            for callee_addr in function_context.callees:
                # We don't have the binary_context here, so just add addresses
                called_funcs.append(f"0x{callee_addr:x}")
            formatted += ", ".join(called_funcs)
        
        # Add strings (key for understanding function purpose)
        if hasattr(function_context, "string_refs") and function_context.string_refs:
            formatted += "\nString references: "
            strings = []
            for addr, string in function_context.string_refs.items():
                if len(string) < 50:  # Only include short strings
                    strings.append(f'"{string}"')
            formatted += ", ".join(strings[:10])  # Limit to 10 strings
            
        return formatted
    
    def get_embedding(self, function_context, binary_name: str = "", force_refresh: bool = False) -> np.ndarray:
        """Get embedding vector for a function
        
        Args:
            function_context: Function to embed
            binary_name: Name of binary (for caching)
            force_refresh: Whether to force refresh cached embedding
            
        Returns:
            NumPy array containing the embedding vector
        """
        # Check if we have a cached embedding
        cache_key = f"{binary_name}_{function_context.name}_{function_context.start_address}"
        
        if not force_refresh and cache_key in self.embeddings_cache:
            return self.embeddings_cache[cache_key]
            
        # Check file cache
        if self.cache_dir and not force_refresh:
            cache_file = os.path.join(
                self.cache_dir,
                f"{binary_name}_{function_context.start_address:x}_embedding.json"
            )
            
            if os.path.exists(cache_file):
                try:
                    with open(cache_file, 'r') as f:
                        data = json.load(f)
                        embedding = np.array(data["embedding"])
                        self.embeddings_cache[cache_key] = embedding
                        return embedding
                except Exception:
                    pass  # Fall through to generate new embedding
        
        # Format the function
        function_text = self._format_function_for_embedding(function_context)
        
        # Get embedding from LLM provider
        try:
            # This would need to be implemented in LLMProcessor
            # For now, we'll assume it returns a numpy array
            embedding = self._get_embedding_from_provider(function_text)
            
            # Cache the result
            self.embeddings_cache[cache_key] = embedding
            
            # Save to file cache
            if self.cache_dir:
                cache_file = os.path.join(
                    self.cache_dir,
                    f"{binary_name}_{function_context.start_address:x}_embedding.json"
                )
                
                with open(cache_file, 'w') as f:
                    json.dump({
                        "function_name": function_context.name,
                        "address": function_context.start_address,
                        "embedding": embedding.tolist()
                    }, f)
            
            return embedding
            
        except Exception as e:
            print(f"Error getting embedding: {e}")
            # Return a zero vector as fallback
            return np.zeros(1536)  # OpenAI embedding dimension
    
    def _get_embedding_from_provider(self, text: str) -> np.ndarray:
        """Get embedding from LLM provider
        
        Args:
            text: Text to embed
            
        Returns:
            NumPy array containing the embedding vector
        """
        # This implementation depends on the LLM provider
        # For OpenAI, we'd use their embeddings API
        
        # Note: For now, this is a placeholder implementation
        # In a real implementation, we would:
        # 1. Call the embedding API
        # 2. Extract the embedding vector
        # 3. Convert to numpy array
        
        if self.llm_config.provider == "openai":
            # Example embedding code for OpenAI
            import openai
            openai.api_key = self.llm_config.api_key
            
            response = openai.Embedding.create(
                model="text-embedding-ada-002",
                input=text
            )
            
            return np.array(response["data"][0]["embedding"])
        else:
            # For other providers, we'd need to implement their specific API calls
            raise NotImplementedError(f"Embedding not implemented for provider: {self.llm_config.provider}")


class SemanticFunctionMatcher:
    """Find semantically similar functions using LLM embeddings"""
    
    def __init__(self, 
                 binary_context: BinaryContext, 
                 embedder: Optional[LLMFunctionEmbedder] = None,
                 cache_dir: Optional[str] = None):
        """Initialize the function matcher
        
        Args:
            binary_context: BinaryContext to analyze
            embedder: LLMFunctionEmbedder instance (optional)
            cache_dir: Directory to cache results (optional)
        """
        self.binary_context = binary_context
        
        # Create embedder if not provided
        if embedder is None:
            self.embedder = LLMFunctionEmbedder(cache_dir=cache_dir)
        else:
            self.embedder = embedder
            
        # Setup caching
        self.cache_dir = cache_dir
        
        # Track embedded functions
        self.function_embeddings = {}
    
    def compute_embeddings(self, max_functions: int = 0, progress_callback: Optional[callable] = None) -> int:
        """Compute embeddings for all functions in the binary
        
        Args:
            max_functions: Maximum number of functions to embed (0 for all)
            progress_callback: Callback function for progress updates
            
        Returns:
            Number of functions embedded
        """
        functions_to_embed = list(self.binary_context.function_context_dict.values())
        
        # Limit the number of functions if specified
        if max_functions > 0 and max_functions < len(functions_to_embed):
            functions_to_embed = functions_to_embed[:max_functions]
            
        total = len(functions_to_embed)
        embedded = 0
        
        for i, function in enumerate(functions_to_embed):
            # Skip thunks (import wrappers) as they're not interesting for similarity
            if function.is_thunk:
                continue
                
            try:
                # Get embedding
                embedding = self.embedder.get_embedding(
                    function, 
                    binary_name=self.binary_context.name
                )
                
                # Store embedding
                self.function_embeddings[function.start_address] = embedding
                embedded += 1
                
                # Report progress
                if progress_callback:
                    progress_callback(i + 1, total, function.name)
                    
            except Exception as e:
                print(f"Error embedding function {function.name}: {e}")
        
        return embedded
    
    def find_similar_functions(self, 
                               function_addr: int, 
                               threshold: float = 0.8,
                               max_results: int = 10) -> List[Dict[str, Any]]:
        """Find functions similar to the target function
        
        Args:
            function_addr: Address of target function
            threshold: Similarity threshold (0-1)
            max_results: Maximum number of results to return
            
        Returns:
            List of similar functions with similarity scores
        """
        if function_addr not in self.binary_context.function_context_dict:
            raise ValueError(f"Function not found at address 0x{function_addr:x}")
            
        target_function = self.binary_context.function_context_dict[function_addr]
        
        # Get target function embedding
        if function_addr not in self.function_embeddings:
            target_embedding = self.embedder.get_embedding(
                target_function,
                binary_name=self.binary_context.name
            )
            self.function_embeddings[function_addr] = target_embedding
        else:
            target_embedding = self.function_embeddings[function_addr]
            
        # Calculate similarity with all other functions
        similarities = []
        
        for addr, embedding in self.function_embeddings.items():
            if addr == function_addr:
                continue  # Skip self
                
            # Calculate cosine similarity (1 - cosine distance)
            similarity = 1 - cosine(target_embedding, embedding)
            
            if similarity >= threshold:
                function = self.binary_context.function_context_dict[addr]
                similarities.append({
                    "address": addr,
                    "name": function.name,
                    "similarity": similarity,
                    "size": function.end_address - function.start_address
                })
        
        # Sort by similarity (highest first)
        similarities.sort(key=lambda x: x["similarity"], reverse=True)
        
        return similarities[:max_results]
    
    def cluster_similar_functions(self, 
                                 threshold: float = 0.8,
                                 min_cluster_size: int = 2) -> List[Dict[str, Any]]:
        """Find clusters of similar functions
        
        Args:
            threshold: Similarity threshold (0-1)
            min_cluster_size: Minimum size of clusters to return
            
        Returns:
            List of function clusters
        """
        # Ensure we have embeddings
        if not self.function_embeddings:
            raise ValueError("No function embeddings available. Call compute_embeddings() first.")
            
        # Use a simple clustering approach
        # 1. Start with each function as its own cluster
        # 2. Merge clusters if any pair of functions exceed the threshold
        
        # Initialize clusters
        clusters = []
        processed = set()
        
        # Process each function
        for addr1 in self.function_embeddings:
            if addr1 in processed:
                continue
                
            # Start a new cluster
            cluster = [addr1]
            processed.add(addr1)
            
            # Find similar functions
            for addr2 in self.function_embeddings:
                if addr2 in processed or addr2 == addr1:
                    continue
                    
                # Calculate similarity
                emb1 = self.function_embeddings[addr1]
                emb2 = self.function_embeddings[addr2]
                similarity = 1 - cosine(emb1, emb2)
                
                if similarity >= threshold:
                    cluster.append(addr2)
                    processed.add(addr2)
            
            # Add cluster if it meets minimum size
            if len(cluster) >= min_cluster_size:
                # Format cluster info
                cluster_info = {
                    "size": len(cluster),
                    "functions": []
                }
                
                for addr in cluster:
                    function = self.binary_context.function_context_dict[addr]
                    cluster_info["functions"].append({
                        "address": addr,
                        "name": function.name,
                        "size": function.end_address - function.start_address
                    })
                
                clusters.append(cluster_info)
        
        # Sort clusters by size (largest first)
        clusters.sort(key=lambda x: x["size"], reverse=True)
        
        return clusters
