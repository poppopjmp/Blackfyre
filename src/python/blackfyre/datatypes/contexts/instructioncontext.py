from typing import List, Optional
from blackfyre.datatypes.protobuf import function_context_pb2

class InstructionContext(object):
    """Class representing a disassembled instruction"""
    
    __slots__ = ['_address', '_bytes', '_mnemonic', '_operands', '_next_address', '_references']
    
    def __init__(self, address: int, bytes_data: bytes, mnemonic: str, operands: str, next_address: int, references: List[int] = None):
        """Initialize InstructionContext
        
        Args:
            address: Memory address of the instruction
            bytes_data: Raw bytes of the instruction
            mnemonic: Instruction mnemonic (e.g., "mov", "call")
            operands: Instruction operands as a string
            next_address: Address of the next instruction
            references: List of addresses referenced by this instruction
        """
        self._address = address
        self._bytes = bytes_data
        self._mnemonic = mnemonic
        self._operands = operands
        self._next_address = next_address
        self._references = references or []
    
    @classmethod
    def from_pb(cls, instruction_pb: function_context_pb2.Instruction):
        """Create from protobuf object"""
        assert isinstance(instruction_pb, function_context_pb2.Instruction), \
            "Expected a protobuf object of type Instruction"
        
        address = instruction_pb.address
        bytes_data = instruction_pb.bytes
        mnemonic = instruction_pb.mnemonic
        operands = instruction_pb.operands
        next_address = instruction_pb.next_address
        references = [ref for ref in instruction_pb.references]
        
        return cls(address, bytes_data, mnemonic, operands, next_address, references)
    
    def to_pb(self) -> function_context_pb2.Instruction:
        """Convert to protobuf representation"""
        instruction_pb = function_context_pb2.Instruction()
        instruction_pb.address = self._address
        instruction_pb.bytes = self._bytes
        instruction_pb.mnemonic = self._mnemonic
        instruction_pb.operands = self._operands
        instruction_pb.next_address = self._next_address
        instruction_pb.references.extend(self._references)
        return instruction_pb
    
    @property
    def address(self) -> int:
        """Get the address of the instruction"""
        return self._address
    
    @property
    def bytes(self) -> bytes:
        """Get the raw bytes of the instruction"""
        return self._bytes
    
    @property
    def mnemonic(self) -> str:
        """Get the instruction mnemonic"""
        return self._mnemonic
    
    @property
    def operands(self) -> str:
        """Get the instruction operands"""
        return self._operands
    
    @property
    def next_address(self) -> int:
        """Get the address of the next instruction"""
        return self._next_address
    
    @property
    def references(self) -> List[int]:
        """Get the list of addresses referenced by this instruction"""
        return self._references
    
    @property
    def instruction_str(self) -> str:
        """Return a string representation of the instruction"""
        return f"{self._mnemonic} {self._operands}"
    
    def __str__(self) -> str:
        """String representation of the instruction"""
        return f"0x{self._address:x}: {self._mnemonic} {self._operands}"
    
    def __repr__(self) -> str:
        """Detailed string representation of the instruction"""
        return f"InstructionContext(address=0x{self._address:x}, mnemonic='{self._mnemonic}', operands='{self._operands}')"
    
    def __eq__(self, other) -> bool:
        """Check equality with another InstructionContext object"""
        if not isinstance(other, InstructionContext):
            return False
        return (self._address == other._address and
                self._bytes == other._bytes and
                self._mnemonic == other._mnemonic and
                self._operands == other._operands and
                self._next_address == other._next_address)
    
    def __hash__(self) -> int:
        """Hash for use in dictionaries and sets"""
        return hash((self._address, self._mnemonic, self._operands))
