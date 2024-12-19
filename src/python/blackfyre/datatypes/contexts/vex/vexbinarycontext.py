import os

from blackfyre.common import PICKLE_EXT
from blackfyre.utils import setup_custom_logger
from blackfyre.datatypes.contexts.binarycontext import BinaryContext
from blackfyre.datatypes.contexts.vex.vexbbcontext import VexBasicBlockContext
from blackfyre.datatypes.contexts.vex.vexfunctioncontext import VexFunctionContext
from blackfyre.datatypes.contexts.vex.vexinstructcontext import VexInstructionContext
from blackfyre.datatypes.headers.peheader import PEHeader

logger = setup_custom_logger(os.path.splitext(os.path.basename(__file__))[0])


class VexBinaryContext(BinaryContext):
    __slots__ = []  # Since we are not adding attributes for the child class, the slot for the child is empty

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    @classmethod
    def get_pickle_file_path(cls, cache_path, binary_name):
        return os.path.join(cache_path, f"{binary_name}.vex.{PICKLE_EXT}")

    @classmethod
    def _get_function_context_from_pb(cls, func_context_pb, func_string_ref,
                                      caller_to_callees_map, callee_to_callers_map,
                                      endness, word_size, disassembler_type, language_id):
        """
        Overloads the parent class with a VexFunctionContext (versus FunctionContext)
        """

        return VexFunctionContext.from_pb(func_context_pb, func_string_ref,
                                          caller_to_callees_map, callee_to_callers_map, endness,
                                          word_size, disassembler_type, language_id)


