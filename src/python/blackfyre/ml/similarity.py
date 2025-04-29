"""Function similarity detection using machine learning features"""

import numpy as np
from typing import Dict, List, Set, Tuple, Optional, Union
from sklearn.metrics.pairwise import cosine_similarity
from blackfyre.datatypes.contexts.binarycontext import BinaryContext
from blackfyre.ml.feature_extractor import FunctionFeatureExtractor

class FunctionSimilarityDetector:
    """Detect similar functions using extracted features"""
    
    def __init__(self, binary_context: BinaryContext):
        """Initialize the similarity detector
        
        Args:
            binary_context: The BinaryContext to analyze
        """
        self.binary_context = binary_context
        self.feature_extractor = FunctionFeatureExtractor(binary_context)
        self._feature_vectors = None
        self._function_addresses = None
    
    def compute_feature_vectors(self, normalize: bool = True) -> np.ndarray:
        """Compute feature vectors for all functions in the binary
        
        Args:
            normalize: Whether to normalize feature vectors
            
        Returns:
            NumPy array of feature vectors
        """
        # Extract features for all functions
        all_features = self.feature_extractor.extract_features_for_all_functions()
        
        # Convert to numpy array
        X = self.feature_extractor.to_numpy_array(all_features)
        
        # Store function addresses for later reference
        self._function_addresses = [f["address"] for f in all_features]
        
        # Normalize if requested
        if normalize and X.shape[0] > 0:
            # Avoid division by zero
            norms = np.linalg.norm(X, axis=1)
            norms[norms == 0] = 1
            X = X / norms[:, np.newaxis]
        
        self._feature_vectors = X
        return X
    
    def find_similar_functions(self, function_addr: int, threshold: float = 0.8, 
                               max_results: int = 10) -> List[Dict[str, Union[int, float, str]]]:
        """Find functions similar to a target function
        
        Args:
            function_addr: Address of the target function
            threshold: Similarity threshold (0-1)
            max_results: Maximum number of results to return
            
        Returns:
            List of dictionaries containing similar functions and their similarity scores
        """
        # Compute feature vectors if not already done
        if self._feature_vectors is None or self._function_addresses is None:
            self.compute_feature_vectors()
        
        # Find index of target function
        if function_addr not in self._function_addresses:
            raise ValueError(f"Function not found at address {hex(function_addr)}")
        
        target_idx = self._function_addresses.index(function_addr)
        
        # Get target function's feature vector
        target_vector = self._feature_vectors[target_idx].reshape(1, -1)
        
        # Compute similarity to all functions
        similarities = cosine_similarity(target_vector, self._feature_vectors).flatten()
        
        # Get similar functions (excluding self-similarity)
        similar_indices = np.argsort(-similarities)  # Sort in descending order
        similar_indices = similar_indices[similar_indices != target_idx]  # Exclude self
        
        results = []
        for idx in similar_indices:
            if similarities[idx] < threshold:
                break
            
            if len(results) >= max_results:
                break
                
            addr = self._function_addresses[idx]
            function = self.binary_context.function_context_dict[addr]
            
            results.append({
                "address": addr,
                "name": function.name,
                "similarity": float(similarities[idx]),
                "size": function.end_address - function.start_address
            })
        
        return results
    
    def find_clusters(self, n_clusters: int = 10) -> Dict[int, List[int]]:
        """Find clusters of similar functions
        
        Args:
            n_clusters: Number of clusters to identify
            
        Returns:
            Dictionary mapping cluster IDs to lists of function addresses
        """
        from sklearn.cluster import KMeans
        
        # Compute feature vectors if not already done
        if self._feature_vectors is None or self._function_addresses is None:
            self.compute_feature_vectors()
        
        # Skip if we have too few functions
        if len(self._function_addresses) < n_clusters:
            n_clusters = len(self._function_addresses)
        
        if n_clusters <= 1:
            return {0: self._function_addresses}
        
        # Cluster functions using K-means
        kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
        cluster_labels = kmeans.fit_predict(self._feature_vectors)
        
        # Group functions by cluster
        clusters = {}
        for i, label in enumerate(cluster_labels):
            if label not in clusters:
                clusters[label] = []
            clusters[label].append(self._function_addresses[i])
        
        return clusters


class BinarySimilarityDetector:
    """Compare functions across different binaries to detect similarities"""
    
    def __init__(self, binary_a: BinaryContext, binary_b: BinaryContext):
        """Initialize the binary similarity detector
        
        Args:
            binary_a: First binary context
            binary_b: Second binary context
        """
        self.binary_a = binary_a
        self.binary_b = binary_b
        self.feature_extractor_a = FunctionFeatureExtractor(binary_a)
        self.feature_extractor_b = FunctionFeatureExtractor(binary_b)
        self._feature_vectors_a = None
        self._feature_vectors_b = None
        self._function_addresses_a = None
        self._function_addresses_b = None
    
    def compute_feature_vectors(self) -> Tuple[np.ndarray, np.ndarray]:
        """Compute feature vectors for functions in both binaries
        
        Returns:
            Tuple of (features_a, features_b) as NumPy arrays
        """
        # Extract features from binary A
        features_a = self.feature_extractor_a.extract_features_for_all_functions()
        self._function_addresses_a = [f["address"] for f in features_a]
        X_a = self.feature_extractor_a.to_numpy_array(features_a)
        
        # Extract features from binary B
        features_b = self.feature_extractor_b.extract_features_for_all_functions()
        self._function_addresses_b = [f["address"] for f in features_b]
        X_b = self.feature_extractor_b.to_numpy_array(features_b)
        
        # Normalize feature vectors
        if X_a.shape[0] > 0:
            norms_a = np.linalg.norm(X_a, axis=1)
            norms_a[norms_a == 0] = 1
            X_a = X_a / norms_a[:, np.newaxis]
            
        if X_b.shape[0] > 0:
            norms_b = np.linalg.norm(X_b, axis=1)
            norms_b[norms_b == 0] = 1
            X_b = X_b / norms_b[:, np.newaxis]
        
        self._feature_vectors_a = X_a
        self._feature_vectors_b = X_b
        
        return X_a, X_b
    
    def find_similar_functions(self, threshold: float = 0.8, max_results_per_function: int = 3) -> List[Dict]:
        """Find similar functions between the two binaries
        
        Args:
            threshold: Similarity threshold (0-1)
            max_results_per_function: Maximum matches per function
            
        Returns:
            List of dictionaries describing matched functions
        """
        # Compute feature vectors if not already done
        if self._feature_vectors_a is None or self._feature_vectors_b is None:
            self.compute_feature_vectors()
        
        # Compute similarity matrix
        similarity_matrix = cosine_similarity(self._feature_vectors_a, self._feature_vectors_b)
        
        # Find matches
        matches = []
        
        for i in range(len(self._function_addresses_a)):
            # Get the most similar functions from binary B
            similar_indices = np.argsort(-similarity_matrix[i])[:max_results_per_function]
            
            for j in similar_indices:
                similarity = similarity_matrix[i, j]
                if similarity < threshold:
                    continue
                    
                addr_a = self._function_addresses_a[i]
                addr_b = self._function_addresses_b[j]
                
                func_a = self.binary_a.function_context_dict[addr_a]
                func_b = self.binary_b.function_context_dict[addr_b]
                
                matches.append({
                    "function_a": {
                        "address": addr_a,
                        "name": func_a.name,
                        "size": func_a.end_address - func_a.start_address
                    },
                    "function_b": {
                        "address": addr_b,
                        "name": func_b.name,
                        "size": func_b.end_address - func_b.start_address
                    },
                    "similarity": float(similarity)
                })
        
        # Sort by similarity (highest first)
        matches.sort(key=lambda x: x["similarity"], reverse=True)
        
        return matches
    
    def compute_binary_similarity_score(self) -> float:
        """Compute an overall similarity score between the two binaries
        
        Returns:
            Similarity score (0-1)
        """
        # Get matched functions
        matches = self.find_similar_functions(threshold=0.7)
        
        if not matches:
            return 0.0
            
        # Compute weighted average similarity
        total_size = 0
        weighted_sum = 0.0
        
        for match in matches:
            size_a = match["function_a"]["size"]
            size_b = match["function_b"]["size"]
            avg_size = (size_a + size_b) / 2
            
            weighted_sum += match["similarity"] * avg_size
            total_size += avg_size
        
        if total_size == 0:
            return 0.0
            
        return weighted_sum / total_size
