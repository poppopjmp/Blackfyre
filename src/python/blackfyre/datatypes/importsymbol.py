from blackfyre.datatypes.protobuf import binary_context_pb2


class ImportSymbol(object):

    __slots__ = ['_import_name', '_library_name', '_address']

    def __init__(self, import_name, library_name, address):

        # Import Symbol name
        self._import_name = import_name

        # Library
        self._library_name = library_name

        # Address of symbol
        self._address = address

    def to_pb(self, import_symbol_pb=None):

        if import_symbol_pb is None:

            # Create the disassembly function pb message
            import_symbol_pb = binary_context_pb2.ImportSymbol()

        # ***Set the message values***

        # Import Name
        import_symbol_pb.import_name = self._import_name

        # Library Name
        import_symbol_pb.library_name = self._library_name

        # Import Address
        import_symbol_pb.address = self._address

        return import_symbol_pb

    @classmethod
    def from_pb(cls, import_symbol_pb):
        assert isinstance(import_symbol_pb, binary_context_pb2.ImportSymbol), \
            "Expected a protobuf object of type ImportSymbol"

        # Import Name
        import_name = import_symbol_pb.import_name

        # Library Name
        library_name = import_symbol_pb.library_name

        # Address
        address = import_symbol_pb.address

        import_symbol = cls(import_name, library_name, address)

        return import_symbol

    @property
    def import_name(self):
        return self._import_name

    @property
    def library_name(self):
        return self._library_name

    @property
    def address(self):
        return self._address