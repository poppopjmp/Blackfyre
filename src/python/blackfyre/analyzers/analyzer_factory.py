"""
Factory for creating appropriate analyzers for different binary types.
"""

from typing import Dict, List, Optional, Union
from blackfyre.datatypes.contexts.binarycontext import BinaryContext
from blackfyre.analyzers.binary_analyzer import BinaryAnalyzer

def create_analyzer(binary_context: BinaryContext) -> BinaryAnalyzer:
    """
    Create an appropriate analyzer for the given binary context.
    
    Args:
        binary_context: The BinaryContext to analyze
        
    Returns:
        An analyzer instance appropriate for the binary type
    """
    # In the future, this could branch to specialized analyzers based on file type
    # (ELF analyzer, PE analyzer, etc.)
    
    return BinaryAnalyzer(binary_context)
