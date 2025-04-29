from typing import Optional
from blackfyre.datatypes.protobuf import binary_context_pb2

class ExportSymbol(object):
    """Class representing an exported symbol in a binary"""
    
    __slots__ = ['_address', '_name', '_ordinal']
    
    def __init__(self, address: int, name: str, ordinal: Optional[int] = None):
        """Initialize ExportSymbol
        
        Args:
            address: Memory address of the export
            name: Name of the exported symbol
            ordinal: Optional ordinal number for the export
        """
        self._address = address
        self._name = name
        self._ordinal = ordinal
    
    @classmethod
    def from_pb(cls, export_symbol_pb: binary_context_pb2.ExportSymbol):
        """Create from protobuf object"""
        assert isinstance(export_symbol_pb, binary_context_pb2.ExportSymbol), \
            "Expected a protobuf object of type ExportSymbol"
        
        address = export_symbol_pb.address
        name = export_symbol_pb.name
        ordinal = export_symbol_pb.ordinal if export_symbol_pb.HasField('ordinal') else None
        
        return cls(address, name, ordinal)
    
    def to_pb(self) -> binary_context_pb2.ExportSymbol:
        """Convert to protobuf representation"""
        export_pb = binary_context_pb2.ExportSymbol()
        export_pb.address = self._address
        export_pb.name = self._name
        if self._ordinal is not None:
            export_pb.ordinal = self._ordinal
        return export_pb
    
    @property
    def address(self) -> int:
        """Get the address of the export"""
        return self._address
    
    @property
    def name(self) -> str:
        """Get the name of the export"""
        return self._name
    
    @property
    def ordinal(self) -> Optional[int]:
        """Get the ordinal of the export (if available)"""
        return self._ordinal
    
    def __str__(self) -> str:
        """String representation of the export symbol"""
        return f"ExportSymbol(name={self._name}, address=0x{self._address:x})"
    
    def __repr__(self) -> str:
        """Detailed string representation of the export symbol"""
        ordinal_part = f", ordinal={self._ordinal}" if self._ordinal is not None else ""
        return f"ExportSymbol(name={self._name}, address=0x{self._address:x}{ordinal_part})"
    
    def __eq__(self, other) -> bool:
        """Check equality with another ExportSymbol object"""
        if not isinstance(other, ExportSymbol):
            return False
        return (self._address == other._address and
                self._name == other._name and
                self._ordinal == other._ordinal)
                
    def __hash__(self) -> int:
        """Hash for use in dictionaries and sets"""
        return hash((self._address, self._name, self._ordinal))
