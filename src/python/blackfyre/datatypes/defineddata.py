from typing import List

from blackfyre.common import DataType
from blackfyre.datatypes.protobuf import binary_context_pb2


class DefinedData(object):
    __slots__ = ['_address', '_data_bytes', '_data_type', '_length', '_references']

    def __init__(self, address: int, data_bytes, data_type: DataType, length: int, references: List[int]):
        self._address: int = address
        self._data_bytes = data_bytes
        self._data_type: DataType = data_type
        self._length: int = length
        self._references: List[int] = references

    @classmethod
    def from_pb(cls, defined_data_pb: binary_context_pb2.DefinedData):
        assert isinstance(defined_data_pb, binary_context_pb2.DefinedData), \
            "Expected a protobuf object of type DefinedData"

        # Address
        address = defined_data_pb.address

        # Data Bytes
        data_bytes = defined_data_pb.data_bytes

        # Data Type
        data_type = DataType(defined_data_pb.data_type)

        # References
        references = [reference for reference in defined_data_pb.references]

        # Length
        length = defined_data_pb.length

        defined_data = cls(address, data_bytes, data_type, length, references)

        return defined_data

    @property
    def address(self) -> int:
        """Get the address of the defined data"""
        return self._address

    @property
    def data_bytes(self) -> bytes:
        """Get the raw bytes of the defined data"""
        return self._data_bytes

    @property
    def data_type(self) -> DataType:
        """Get the data type of the defined data"""
        return self._data_type

    @property
    def length(self) -> int:
        """Get the length of the defined data"""
        return self._length

    @property
    def references(self) -> List[int]:
        """Get the list of references to this defined data"""
        return self._references
        
    def to_pb(self) -> binary_context_pb2.DefinedData:
        """Convert to protobuf representation"""
        defined_data_pb = binary_context_pb2.DefinedData()
        defined_data_pb.address = self._address
        defined_data_pb.data_bytes = self._data_bytes
        defined_data_pb.data_type = self._data_type.value
        defined_data_pb.length = self._length
        defined_data_pb.references.extend(self._references)
        return defined_data_pb
        
    def __str__(self) -> str:
        """Return string representation"""
        return f"DefinedData(address=0x{self._address:x}, type={self._data_type.name}, length={self._length})"
        
    def __repr__(self) -> str:
        """Return detailed string representation"""
        return f"DefinedData(address=0x{self._address:x}, data_type={self._data_type}, length={self._length}, references={self._references})"
        
    def __eq__(self, other) -> bool:
        """Check equality with another DefinedData object"""
        if not isinstance(other, DefinedData):
            return False
        return (self._address == other._address and
                self._data_bytes == other._data_bytes and
                self._data_type == other._data_type and
                self._length == other._length and
                self._references == other._references)
                
    def __hash__(self) -> int:
        """Hash for use in dictionaries and sets"""
        return hash((self._address, self._data_type, self._length))
