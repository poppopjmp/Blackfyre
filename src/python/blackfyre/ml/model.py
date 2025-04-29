"""Machine learning model training and inference for binary analysis"""

import os
import json
import pickle
import numpy as np
from typing import Dict, List, Set, Tuple, Optional, Union, Any
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_recall_fscore_support
from blackfyre.datatypes.contexts.binarycontext import BinaryContext
from blackfyre.ml.feature_extractor import FunctionFeatureExtractor

class FunctionClassifier:
    """Machine learning classifier for functions in binaries"""
    
    def __init__(self, model_type: str = "random_forest"):
        """Initialize the function classifier
        
        Args:
            model_type: Type of model to use ("random_forest", etc.)
        """
        self.model_type = model_type
        self.model = None
        self.feature_names = None
        self.classes = None
        
    def create_model(self):
        """Create a new model based on the specified type"""
        if self.model_type == "random_forest":
            self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        else:
            raise ValueError(f"Unsupported model type: {self.model_type}")
            
        return self.model
    
    def prepare_training_data(self, feature_list: List[Dict], labels: List[str]) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare training data from feature dictionaries
        
        Args:
            feature_list: List of feature dictionaries
            labels: List of class labels corresponding to features
            
        Returns:
            Tuple of (X, y) arrays for training
        """
        # Extract feature names (excluding non-numeric and address features)
        self.feature_names = [k for k, v in feature_list[0].items() 
                             if isinstance(v, (int, float)) and k not in ('address')]
        
        # Convert features to numpy array
        X = np.zeros((len(feature_list), len(self.feature_names)))
        
        for i, features in enumerate(feature_list):
            for j, feature_name in enumerate(self.feature_names):
                X[i, j] = features.get(feature_name, 0)
        
        # Convert labels to numpy array
        unique_labels = sorted(set(labels))
        self.classes = unique_labels
        
        label_to_idx = {label: i for i, label in enumerate(unique_labels)}
        y = np.array([label_to_idx[label] for label in labels])
        
        return X, y
    
    def train(self, feature_list: List[Dict], labels: List[str], test_size: float = 0.2) -> Dict[str, float]:
        """Train the model on the provided data
        
        Args:
            feature_list: List of feature dictionaries
            labels: List of class labels corresponding to features
            test_size: Proportion of data to use for testing
            
        Returns:
            Dictionary of evaluation metrics
        """
        # Prepare data
        X, y = self.prepare_training_data(feature_list, labels)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )
        
        # Create and train model
        if self.model is None:
            self.create_model()
            
        self.model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        precision, recall, f1, _ = precision_recall_fscore_support(
            y_test, y_pred, average='weighted'
        )
        
        return {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "num_features": len(self.feature_names),
            "num_classes": len(self.classes),
            "train_samples": len(X_train),
            "test_samples": len(X_test)
        }
    
    def predict_function(self, features: Dict) -> Dict[str, Union[str, float]]:
        """Predict the class of a function from its features
        
        Args:
            features: Dictionary of function features
            
        Returns:
            Dictionary with prediction results
        """
        if self.model is None:
            raise ValueError("Model not trained yet")
            
        # Extract feature values
        X = np.zeros((1, len(self.feature_names)))
        for i, feature_name in enumerate(self.feature_names):
            X[0, i] = features.get(feature_name, 0)
            
        # Make prediction
        class_idx = self.model.predict(X)[0]
        class_label = self.classes[class_idx]
        
        # Get class probabilities
        probabilities = self.model.predict_proba(X)[0]
        confidence = float(probabilities[class_idx])
        
        return {
            "predicted_class": class_label,
            "confidence": confidence,
            "probabilities": {self.classes[i]: float(p) for i, p in enumerate(probabilities)}
        }
    
    def predict_functions_in_binary(self, binary_context: BinaryContext) -> Dict[int, Dict[str, Any]]:
        """Predict classes for all functions in a binary
        
        Args:
            binary_context: The BinaryContext to analyze
            
        Returns:
            Dictionary mapping function addresses to prediction results
        """
        # Extract features for all functions
        feature_extractor = FunctionFeatureExtractor(binary_context)
        all_features = feature_extractor.extract_features_for_all_functions()
        
        # Make predictions
        results = {}
        for features in all_features:
            addr = features["address"]
            try:
                prediction = self.predict_function(features)
                results[addr] = {
                    "name": features["name"],
                    **prediction
                }
            except Exception as e:
                print(f"Error predicting function at {hex(addr)}: {e}")
        
        return results
    
    def save_model(self, path: str):
        """Save the model to a file
        
        Args:
            path: Path to save the model
        """
        if self.model is None:
            raise ValueError("No model to save")
            
        # Save model with pickle
        with open(path, 'wb') as f:
            pickle.dump({
                "model": self.model,
                "feature_names": self.feature_names,
                "classes": self.classes,
                "model_type": self.model_type
            }, f)
    
    @classmethod
    def load_model(cls, path: str) -> 'FunctionClassifier':
        """Load a model from a file
        
        Args:
            path: Path to load the model from
            
        Returns:
            FunctionClassifier instance with the loaded model
        """
        with open(path, 'rb') as f:
            data = pickle.load(f)
            
        classifier = cls(model_type=data["model_type"])
        classifier.model = data["model"]
        classifier.feature_names = data["feature_names"]
        classifier.classes = data["classes"]
        
        return classifier
