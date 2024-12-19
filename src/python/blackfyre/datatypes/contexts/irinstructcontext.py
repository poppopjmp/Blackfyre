

class IRInstructionContext(object):

    __slots__ = ['_instruction', '_category', '_native_address', '_native_instruction_size']

    def __init__(self, instruction, native_address, native_instruction_size):

        self._instruction = instruction

        self._native_address = native_address

        self._native_instruction_size = native_instruction_size

    @property
    def instruction(self):
        return self._instruction

    @property
    def native_address(self):
        return self._native_address

    @property
    def native_instruction_size(self):
        return self._native_instruction_size

    @property
    def category(self):
        raise NotImplementedError("Expected category to be implemented by child class")



