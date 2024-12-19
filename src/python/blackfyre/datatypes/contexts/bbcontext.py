from typing import List

from blackfyre.common import ProcessorType
from blackfyre.datatypes.contexts.nativeinstructcontext import NativeInstructionContext
from blackfyre.datatypes.protobuf import function_context_pb2


class BasicBlockContext(object):
    __slots__ = ['_start_address', '_end_address', '_instruction_contexts', '_size', '_proc_type']

    def __init__(self,
                 start_address,
                 end_address,
                 instruction_contexts,
                 proc_type):

        # Basic Block start address
        self._start_address = start_address

        # Basic Block end address
        self._end_address = end_address

        # Size of the basic block
        self._size = end_address - start_address

        # List of the instruction contexts
        if instruction_contexts is None:
            self._instruction_contexts = []
        else:
            self._instruction_contexts = instruction_contexts

        # Processor Type
        self._proc_type = proc_type

    @classmethod
    def from_pb(cls, basic_block_context_pb):

        assert isinstance(basic_block_context_pb, function_context_pb2.BasicBlockContext), \
            "Expected a protobuf object of type DisassemblyBasicBlock"

        # Start address
        start_address = basic_block_context_pb.start_address

        # End address
        end_address = basic_block_context_pb.end_address

        # Disassembly instruction list
        instruction_contexts = [NativeInstructionContext.from_pb(instruction_context_pb)
                                for instruction_context_pb in basic_block_context_pb.instruction_context_list]

        # Processor Type
        proc_type = ProcessorType(basic_block_context_pb.proc_type)

        # Create the disassembly function object
        basic_block_context = cls(start_address, end_address, instruction_contexts, proc_type)

        return basic_block_context

    # def to_pb(self, disassembly_basicblock_pb=None):
    #
    #     if disassembly_basicblock_pb is None:
    #         # Create the disassembly function pb message
    #         disassembly_basicblock_pb = disassembly_pb2.DisassemblyBasicBlock()
    #
    #     # Start address
    #     disassembly_basicblock_pb.start_address = self.start_address
    #
    #     # End address
    #     disassembly_basicblock_pb.end_address = self.end_address
    #
    #     # Add the disassembly instruction messages to the function
    #     for disassembly_instruction in self.instruction_contexts:
    #         # Add a disassembly instruction message
    #         disassembly_instruction_pb = disassembly_basicblock_pb.disassembly_instruct_list.add()
    #
    #         # populate the disassembly instruction message
    #         disassembly_instruction.to_pb(disassembly_instruction_pb)
    #
    #     return disassembly_basicblock_pb

    @property
    def start_address(self) -> int:
        return self._start_address

    @property
    def end_address(self) -> int:
        return self._end_address

    @property
    def native_instruction_contexts(self) -> List[NativeInstructionContext]:
        for instruction_context in sorted(self._instruction_contexts, key=lambda x: x.address):
            yield instruction_context

    @property
    def proc_type(self):
        return self._proc_type
