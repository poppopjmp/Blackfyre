from enum import Enum
from pathlib import Path
import os

# ++++=========================CONSTANTS =========================================
LOG_DIR = os.path.join(os.path.expanduser('~'), 'Blackfyre', 'logs')
MAX_BINARY_NAME_LENGTH = 50
BINARY_CONTEXT_CONTAINER_EXT = "bcc"
PICKLE_EXT = "p"

DEFAULT_CACHE_DIR = os.path.join(Path.home(), ".cache", "blackfyre")


# ==========================END CONSTANTS ===================================

class DataType(Enum):
    WORD = 1
    DWORD = 2
    QWORD = 3
    POINTER32 = 4
    POINTER64 = 5


class ProcessorType(Enum):
    x86 = 1
    x86_64 = 2
    ARM = 3
    PPC = 4
    MIPS = 5
    AARCH64 = 6


class Endness(Enum):
    BIG_ENDIAN = 1
    LITTLE_ENDIAN = 2


class FileType(Enum):
    PE32 = 1
    PE64 = 2
    ELF32 = 3
    ELF64 = 4
    MACH_O_32 = 5
    MACH_O_64 = 6


class ArchWordSize(Enum):
    BITS_32 = 1
    BITS_64 = 2
    BITS_16 = 3


class MessageType(Enum):
    BINARY_CONTEXT_MSG = 1
    FUNCTION_CONTEXT_MSG = 2
    RAW_BINARY_MSG = 3


class DisassemblerType(Enum):
    GHIDRA = 1
    IDA_PRO = 2
    BINARY_NINJA = 3


class IRCategory(Enum):
    arithmetic = 0
    call = 1
    load = 2
    store = 3
    branch = 4
    bit_logic = 5
    bit_shift = 6
    bit_extend = 7
    bit_trunc = 8
    reg_access = 9
    compare = 10
    ret = 11
    other = 12
