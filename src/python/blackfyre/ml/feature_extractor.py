"""Feature extraction for machine learning on binary code"""

import numpy as np
from typing import Dict, List, Set, Optional, Union
from blackfyre.datatypes.contexts.binarycontext import BinaryContext
from blackfyre.datatypes.contexts.functioncontext import FunctionContext

class FunctionFeatureExtractor:
    """Extract features from functions for machine learning models"""
    
    def __init__(self, binary_context: BinaryContext):
        """Initialize the feature extractor
        
        Args:
            binary_context: The BinaryContext to extract features from
        """
        self.binary_context = binary_context
        
    def extract_basic_features(self, function: FunctionContext) -> Dict:
        """Extract basic features from a function
        
        Args:
            function: The FunctionContext to extract features from
            
        Returns:
            Dictionary of features
        """
        # Count instructions by type
        instruction_types = {}
        instruction_count = 0
        
        for bb in function.basic_block_contexts:
            for instr in bb.instruction_contexts:
                if hasattr(instr, 'mnemonic'):
                    mnemonic = instr.mnemonic.lower()
                    instruction_types[mnemonic] = instruction_types.get(mnemonic, 0) + 1
                    instruction_count += 1
        
        # Calculate feature values
        features = {
            "instruction_count": function.total_instructions,
            "basic_block_count": len(function.basic_block_contexts),
            "callee_count": len(function.callees),
            "is_thunk": int(function.is_thunk),
            "avg_instructions_per_block": function.total_instructions / max(1, len(function.basic_block_contexts)),
            "size": function.end_address - function.start_address,
        }
        
        # Instruction categories
        control_flow = ["jmp", "je", "jne", "jz", "jnz", "call", "ret", "loop"]
        arithmetic = ["add", "sub", "mul", "div", "inc", "dec", "imul", "idiv"]
        data_movement = ["mov", "lea", "push", "pop", "xchg"]
        logical = ["and", "or", "xor", "not", "shl", "shr", "sar", "rol", "ror"]
        
        # Add instruction category counts
        features["control_flow_count"] = sum(instruction_types.get(i, 0) for i in control_flow)
        features["arithmetic_count"] = sum(instruction_types.get(i, 0) for i in arithmetic)
        features["data_movement_count"] = sum(instruction_types.get(i, 0) for i in data_movement)
        features["logical_count"] = sum(instruction_types.get(i, 0) for i in logical)
        
        # Add instruction category ratios
        if instruction_count > 0:
            features["control_flow_ratio"] = features["control_flow_count"] / instruction_count
            features["arithmetic_ratio"] = features["arithmetic_count"] / instruction_count
            features["data_movement_ratio"] = features["data_movement_count"] / instruction_count
            features["logical_ratio"] = features["logical_count"] / instruction_count
        else:
            features["control_flow_ratio"] = 0
            features["arithmetic_ratio"] = 0
            features["data_movement_ratio"] = 0
            features["logical_ratio"] = 0
        
        return features
    
    def extract_string_features(self, function: FunctionContext) -> Dict:
        """Extract string-related features from a function
        
        Args:
            function: The FunctionContext to extract features from
            
        Returns:
            Dictionary of string features
        """
        # Find strings referenced by this function
        string_refs = {}
        if hasattr(function, 'string_refs'):
            string_refs = function.string_refs
        
        # Calculate string features
        features = {
            "string_ref_count": len(string_refs),
            "avg_string_length": sum(len(s) for s in string_refs.values()) / max(1, len(string_refs)),
            "max_string_length": max((len(s) for s in string_refs.values()), default=0),
        }
        
        return features
    
    def extract_all_features(self, function_addr: int) -> Dict:
        """Extract all features for a function
        
        Args:
            function_addr: Address of the function to extract features from
            
        Returns:
            Dictionary of all features
        """
        # Get the function by address
        if function_addr not in self.binary_context.function_context_dict:
            raise ValueError(f"Function not found at address {hex(function_addr)}")
        
        function = self.binary_context.function_context_dict[function_addr]
        
        # Extract all feature types
        basic_features = self.extract_basic_features(function)
        string_features = self.extract_string_features(function)
        
        # Combine features
        features = {
            "address": function_addr,
            "name": function.name,
            **basic_features,
            **string_features
        }
        
        return features
    
    def extract_features_for_all_functions(self) -> List[Dict]:
        """Extract features for all functions in the binary
        
        Returns:
            List of feature dictionaries, one for each function
        """
        all_features = []
        
        for addr in self.binary_context.function_context_dict:
            try:
                features = self.extract_all_features(addr)
                all_features.append(features)
            except Exception as e:
                print(f"Error extracting features for function at {hex(addr)}: {e}")
        
        return all_features
    
    def to_numpy_array(self, feature_list: List[Dict], feature_names: Optional[List[str]] = None) -> np.ndarray:
        """Convert feature dictionaries to a numpy array
        
        Args:
            feature_list: List of feature dictionaries
            feature_names: List of feature names to include (default: all numeric features)
            
        Returns:
            Numpy array of features, shape (n_samples, n_features)
        """
        if not feature_list:
            return np.array([])
        
        # If feature names not provided, use all numeric features from first dict
        if feature_names is None:
            feature_names = [k for k, v in feature_list[0].items() 
                            if isinstance(v, (int, float)) and k not in ('address')]
        
        # Extract the specified features into a 2D array
        X = np.zeros((len(feature_list), len(feature_names)))
        
        for i, features in enumerate(feature_list):
            for j, feature_name in enumerate(feature_names):
                X[i, j] = features.get(feature_name, 0)
        
        return X
