import os.path
from blackfyre.datatypes.contexts.binarycontext import BinaryContext

# Get the absolute path to the Blackfyre repository relative to this script's location
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))  # Directory of the current script
PATH_TO_BLACKFYRE_REPO = os.path.abspath(os.path.join(SCRIPT_DIR, "..", ".."))  # Backtrack to 'Blackfyre'


# Test bcc file path included in the repository
bcc_file_path = os.path.join(PATH_TO_BLACKFYRE_REPO, "test/bison_arm_9409117ee68a2d75643bb0e0a15c71ab52d4e90f_9409117ee68a2d75643bb0e0a15c71ab52d4e90fa066e419b1715e029bcdc3dd.bcc")

# Load the appropriate binary context with the determined cache path
binary_context = BinaryContext.load_from_file(bcc_file_path)

# Display basic meta-data about the binary
print(f"Binary Name: {binary_context.name}")
print(f"Binary SHA256: {binary_context.sha256_hash}")
print(f"Binary File Type: {binary_context.file_type}")
print(f"Processor Type: {binary_context.proc_type}")
print(f"Number of Functions: {len(binary_context.function_context_dict)}")
print(f"Number of Strings: {len(binary_context.string_refs)}")
print(f"Number of Import Functions: {len(binary_context.import_symbols)}")
print(f"Number of Export Functions: {len(binary_context.export_symbols)}")
print(f"Number of Defined Data: {len(binary_context.defined_data_map)}")
print(f"Disassembly Type: {binary_context.disassembler_type}")
print(f"Endianness: {binary_context.endness}")
print(f"Disassembler Version: {binary_context.disassembler_version}")
print(f"BCC File Version: {binary_context.bcc_version}")

# Print the function names in the binary context container (bcc) file
num_functions_to_display = 5
max_decompiled_code_length = 100
print(f"\nDisplaying up to {num_functions_to_display} Functions:")
counter = 0
for index, function_context in enumerate(binary_context.function_contexts):

    print("=" * 100)
    print(f"  - Function Name: {function_context.name}")
    print(f"  - Function Start Address: {function_context.address}")
    print(f"  - Function End Address: {function_context.end_address}")
    print(f"  - Function Size: {function_context.size}")
    print(f"  - Function Number of Blocks: {len(function_context.basic_block_context_dict)}")
    print(f"  - Function Number of Callers: {len(function_context.callers)}")
    print(f"  - Function Number of Callees: {len(function_context.callees)}")
    print(f"  - Function Number of Unique Callees: {len(set(function_context.callees))}")
    if hasattr(function_context, "all_callees"):
        print(f"  - Function Unique All Callees: {len(function_context.all_callees)}")
    if hasattr(function_context, "num_all_call_sites"):
        print(f"  - Function Number of All Call Sites: {function_context.num_all_call_sites}")
    print(f"  - Function Decompiled Code: {function_context.decompiled_code[:max_decompiled_code_length]}")
    print("=" * 100 + "\n")

    counter += 1
    if counter >= num_functions_to_display:
        break