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
    def address(self):
        return self._address

    @property
    def data_bytes(self):
        return self._data_bytes

    @property
    def data_type(self):
        return self._data_type

    @property
    def length(self):
        return self._length

    @property
    def references(self):
        return self._references
