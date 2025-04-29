"""Customizable prompt templates for LLM-based analysis"""

import os
import json
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

class PromptTemplateManager:
    """Manager for LLM prompt templates"""
    
    # Default templates
    DEFAULT_TEMPLATES = {
        "function_analysis": {
            "system_prompt": """You are a binary code analysis expert. Your task is to analyze and explain the 
            provided function. Focus on:
            1. What the function does (its purpose)
            2. Key algorithms or operations performed
            3. Security implications (if any)
            4. Return values and parameters
            5. Interesting observations
            
            Provide a clear, concise explanation in a professional tone.""",
            
            "user_prompt": """Please analyze this function from a binary and explain what it does:
            
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
            [Any other interesting observations]"""
        },
        
        "vulnerability_assessment": {
            "system_prompt": """You are an expert in security vulnerability assessment. Your task is to analyze
            the provided function and identify any potential security vulnerabilities.
            
            Focus on:
            1. Buffer overflows
            2. Format string vulnerabilities
            3. Integer overflows/underflows
            4. Use-after-free
            5. Race conditions
            6. Command/SQL injection
            7. Other memory safety issues
            
            Be specific and cite evidence from the code. If you're uncertain, indicate your confidence level.""",
            
            "user_prompt": """Please analyze this function for potential security vulnerabilities:
            
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
            [How to address these vulnerabilities]"""
        },
        
        "binary_summary": {
            "system_prompt": """You are a binary analysis expert. Your task is to provide a comprehensive summary of a binary
            based on its metadata, imports, exports, and strings. Focus on:
            1. Likely purpose/functionality of the binary
            2. Programming language or framework used
            3. Key capabilities based on imports
            4. Security implications (if any)
            5. Any notable observations
            
            Provide a clear, structured analysis in markdown format.""",
            
            "user_prompt": """Please analyze this binary and provide a summary:
            
            ## Binary Information
            - Name: {binary_name}
            - Architecture: {architecture}
            - Number of functions: {function_count}
            - Number of imports: {import_count}
            - Number of exports: {export_count}
            - Number of strings: {string_count}
            
            ## Key Imports
            {imports}
            
            ## Key Exports
            {exports}
            
            ## Interesting Strings
            {strings}
            
            Please provide a comprehensive analysis of this binary in markdown format,
            including its likely purpose, programming language/framework, capabilities,
            and any security implications."""
        }
    }
    
    def __init__(self, config_path: Optional[Path] = None):
        """Initialize the prompt template manager
        
        Args:
            config_path: Path to template configuration file (YAML/JSON)
        """
        self.templates = self.DEFAULT_TEMPLATES.copy()
        self.config_path = config_path
        
        if config_path:
            self.load_templates(config_path)
    
    def load_templates(self, config_path: Path) -> bool:
        """Load templates from a configuration file
        
        Args:
            config_path: Path to configuration file
            
        Returns:
            True if templates were loaded successfully
        """
        if not os.path.exists(config_path):
            return False
            
        try:
            ext = os.path.splitext(config_path)[1].lower()
            
            if ext == '.json':
                with open(config_path, 'r') as f:
                    custom_templates = json.load(f)
            elif ext in ('.yaml', '.yml'):
                with open(config_path, 'r') as f:
                    custom_templates = yaml.safe_load(f)
            else:
                return False
                
            # Merge custom templates with defaults
            for template_name, template in custom_templates.items():
                if template_name in self.templates:
                    # Update existing template
                    for key, value in template.items():
                        self.templates[template_name][key] = value
                else:
                    # Add new template
                    self.templates[template_name] = template
                    
            return True
            
        except Exception as e:
            print(f"Error loading templates: {e}")
            return False
    
    def get_template(self, template_name: str) -> Dict[str, str]:
        """Get a prompt template by name
        
        Args:
            template_name: Name of the template
            
        Returns:
            Dictionary with system_prompt and user_prompt
        """
        if template_name not in self.templates:
            raise ValueError(f"Template not found: {template_name}")
            
        return self.templates[template_name]
    
    def list_templates(self) -> List[str]:
        """List all available templates
        
        Returns:
            List of template names
        """
        return sorted(list(self.templates.keys()))
    
    def format_prompt(self, template_name: str, **kwargs) -> Dict[str, str]:
        """Format a prompt template with the given parameters
        
        Args:
            template_name: Name of the template
            **kwargs: Parameters to format the template with
            
        Returns:
            Dictionary with formatted system_prompt and user_prompt
        """
        template = self.get_template(template_name)
        
        return {
            "system_prompt": template["system_prompt"].format(**kwargs),
            "user_prompt": template["user_prompt"].format(**kwargs)
        }
    
    def save_templates(self, output_path: Optional[Path] = None) -> bool:
        """Save templates to a configuration file
        
        Args:
            output_path: Path to save the templates to (defaults to self.config_path)
            
        Returns:
            True if templates were saved successfully
        """
        path = output_path or self.config_path
        
        if not path:
            return False
            
        try:
            ext = os.path.splitext(path)[1].lower()
            
            if ext == '.json':
                with open(path, 'w') as f:
                    json.dump(self.templates, f, indent=2)
            elif ext in ('.yaml', '.yml'):
                with open(path, 'w') as f:
                    yaml.dump(self.templates, f, default_flow_style=False)
            else:
                # Default to JSON
                with open(path, 'w') as f:
                    json.dump(self.templates, f, indent=2)
                    
            return True
            
        except Exception as e:
            print(f"Error saving templates: {e}")
            return False
            
    def create_template(self, name: str, system_prompt: str, user_prompt: str) -> bool:
        """Create a new template
        
        Args:
            name: Name for the new template
            system_prompt: System prompt content
            user_prompt: User prompt content
            
        Returns:
            True if template was created successfully
        """
        if name in self.templates:
            print(f"Template '{name}' already exists. Use update_template to modify it.")
            return False
            
        self.templates[name] = {
            "system_prompt": system_prompt,
            "user_prompt": user_prompt
        }
        
        return True
    
    def update_template(self, name: str, system_prompt: Optional[str] = None, 
                       user_prompt: Optional[str] = None) -> bool:
        """Update an existing template
        
        Args:
            name: Name of template to update
            system_prompt: New system prompt (if None, keep existing)
            user_prompt: New user prompt (if None, keep existing)
            
        Returns:
            True if template was updated successfully
        """
        if name not in self.templates:
            print(f"Template '{name}' doesn't exist. Use create_template to create it.")
            return False
            
        if system_prompt is not None:
            self.templates[name]["system_prompt"] = system_prompt
            
        if user_prompt is not None:
            self.templates[name]["user_prompt"] = user_prompt
            
        return True
    
    def delete_template(self, name: str) -> bool:
        """Delete a template
        
        Args:
            name: Name of template to delete
            
        Returns:
            True if template was deleted successfully
        """
        if name not in self.templates:
            print(f"Template '{name}' doesn't exist.")
            return False
            
        # Don't allow deleting default templates
        if name in self.DEFAULT_TEMPLATES:
            print(f"Cannot delete default template '{name}'.")
            return False
            
        del self.templates[name]
        return True
    
    def validate_template(self, name: str) -> Tuple[bool, List[str]]:
        """Validate a template for required parameters
        
        Args:
            name: Name of template to validate
            
        Returns:
            Tuple of (is_valid, missing_parameters)
        """
        if name not in self.templates:
            return False, [f"Template '{name}' doesn't exist"]
            
        template = self.templates[name]
        missing = []
        
        # Get all parameters from the user prompt
        import re
        params = set(re.findall(r'\{([^}]+)\}', template["user_prompt"]))
        
        # These are standard parameters that should be present in most templates
        standard_params = ["binary_name", "architecture"]
        
        for param in standard_params:
            if param not in params:
                missing.append(f"Template is missing standard parameter: {param}")
                
        # Specific validation for known template types
        if name == "function_analysis" and "function_text" not in params:
            missing.append("function_analysis template is missing 'function_text' parameter")
            
        if name == "binary_summary" and "function_count" not in params:
            missing.append("binary_summary template is missing 'function_count' parameter")
            
        is_valid = len(missing) == 0
        return is_valid, missing
    
    def compose_templates(self, base_name: str, extension_name: str, new_name: str) -> bool:
        """Compose two templates by extending a base template
        
        Args:
            base_name: Name of base template
            extension_name: Name of extension template
            new_name: Name for the new composed template
            
        Returns:
            True if templates were composed successfully
        """
        if base_name not in self.templates:
            print(f"Base template '{base_name}' doesn't exist.")
            return False
            
        if extension_name not in self.templates:
            print(f"Extension template '{extension_name}' doesn't exist.")
            return False
            
        # Get templates
        base = self.templates[base_name]
        extension = self.templates[extension_name]
        
        # Compose new system prompt
        system_prompt = f"{base['system_prompt']}\n\nAdditional instructions:\n{extension['system_prompt']}"
        
        # Compose new user prompt
        user_prompt = f"{base['user_prompt']}\n\nAdditional context:\n{extension['user_prompt']}"
        
        # Create new template
        self.templates[new_name] = {
            "system_prompt": system_prompt,
            "user_prompt": user_prompt
        }
        
        return True
