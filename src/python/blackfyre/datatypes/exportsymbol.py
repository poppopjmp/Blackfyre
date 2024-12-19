from blackfyre.datatypes.protobuf import binary_context_pb2


class ExportSymbol(object):
    __slots__ = ['_export_name', '_library_name', '_address']

    def __init__(self, export_name, library_name, address):
        # Export Symbol name
        self._export_name = export_name

        # Library
        self._library_name = library_name

        # Address of symbol
        self._address = address

    def to_pb(self, export_symbol_pb=None):
        if export_symbol_pb is None:
            # Create the disassembly function pb message
            export_symbol_pb = binary_context_pb2.ExportSymbol()

        # ***Set the message values***

        # Import Name
        export_symbol_pb.export_name = self._export_name

        # Library Name
        export_symbol_pb.library_name = self._library_name

        # Import Address
        export_symbol_pb.address = self._address

        return export_symbol_pb

    @classmethod
    def from_pb(cls, export_symbol_pb):
        assert isinstance(export_symbol_pb, binary_context_pb2.ExportSymbol), \
            "Expected a protobuf object of type ImportSymbol"

        # Export Name
        export_name = export_symbol_pb.export_name

        # Library Name
        library_name = export_symbol_pb.library_name

        # Address
        address = export_symbol_pb.address

        export_symbol = cls(export_name, library_name, address)

        return export_symbol

    @property
    def export_name(self):
        return self._export_name

    @property
    def library_name(self):
        return self._library_name

    @property
    def address(self):
        return self._address
