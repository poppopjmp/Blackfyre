import argparse

from blackfyre.common import DEFAULT_CACHE_DIR
from blackfyre.datatypes.contexts.vex.vexbinarycontext import VexBinaryContext
from blackfyre.datatypes.contexts.binarycontext import BinaryContext

def load_binary_context(file_path: str, use_vex: bool, cache_path: str) -> BinaryContext:
    if use_vex:
        print("Using VexBinaryContext")
        return VexBinaryContext.load_from_file(file_path, cache_path=cache_path)
    else:
        print("Using BinaryContext")
        return BinaryContext.load_from_file(file_path, cache_path=cache_path)

def display_binary_context_info(binary_context: BinaryContext, num_functions: int, decompiled_code_length: int) -> None:
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
    print(f"\nDisplaying up to {num_functions} Functions:")
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
        print(f"  - Function Decompiled Code: {function_context.decompiled_code[:decompiled_code_length]}")
        print("=" * 100 + "\n")

        counter += 1
        if counter >= num_functions:
            break

def main():
    parser = argparse.ArgumentParser(
        description="Load and display information from a Binary Context Container (BCC) file.")
    parser.add_argument("file_path", type=str, help="Path to the BCC file.")
    parser.add_argument("--use-binary-context", action="store_true",
                        help="Use BinaryContext instead of VexBinaryContext.")
    parser.add_argument("--no-cache", action="store_true", help="Disable caching (enabled by default).")
    parser.add_argument("--num-functions", type=int, default=10, help="Number of functions to display (default is 10).")
    parser.add_argument("--decompiled-code-length", type=int, default=500,
                        help="Length of truncated decompiled code to display (default is 500 characters).")
    parser.add_argument("--cache-path", type=str, default=DEFAULT_CACHE_DIR,
                        help=f"Path to the cache directory (default is {DEFAULT_CACHE_DIR}).")
    args = parser.parse_args()

    # Determine cache path based on the --no-cache flag
    cache_path = None if args.no_cache else args.cache_path

    # Load the appropriate binary context with the determined cache path
    binary_context = load_binary_context(args.file_path, not args.use_binary_context, cache_path)

    # Display the binary context information
    display_binary_context_info(binary_context, args.num_functions, args.decompiled_code_length)

if __name__ == "__main__":
    main()