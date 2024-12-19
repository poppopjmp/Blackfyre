from blackfyre.datatypes.protobuf import function_context_pb2


class NativeInstructionContext(object):

    __slots__ = ['_address', '_opcode_bytes', '_size', '_mnemonic']

    def __init__(self, address, opcode_bytes, mnemonic):

        # Instruction address
        self._address = address

        # Opcode bytes
        self._opcode_bytes = opcode_bytes

        # Get the length of the opcode
        self._size = len(opcode_bytes)

        # Mnemonic
        self._mnemonic = mnemonic

    @classmethod
    def from_pb(cls, instruction_context_pb):
        assert isinstance(instruction_context_pb, function_context_pb2.InstructionContext), \
            "Expected a protobuf object of type DisassemblyInstruction"

        # Address
        address = instruction_context_pb.address

        # Opcode bytes
        opcode_bytes = instruction_context_pb.opcode_bytes

        # Mnemonic
        mnemonic = instruction_context_pb.mnemonic

        instruction_context = cls(address ,opcode_bytes, mnemonic)

        return instruction_context

    def to_pb(self, disassembly_instruction_pb=None):

        # Create the disassembly instruction pb message is one is not passed in
        if disassembly_instruction_pb is None:
            disassembly_instruction_pb = function_context_pb2.InstructionContext()

        # Address
        disassembly_instruction_pb.address = self._address

        # Opcode
        disassembly_instruction_pb.opcode_bytes = self._opcode_bytes

        # Mnemonic
        disassembly_instruction_pb.mnemonic = self._mnemonic

        return disassembly_instruction_pb

    @property
    def address(self):
        return self._address

    @property
    def opcode_bytes(self):
        return self._opcode_bytes

    @property
    def mnemonic(self):
        return self._mnemonic

    @property
    def size(self):
        return self._size


