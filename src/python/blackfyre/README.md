# Installing Blackfyre Python Library
To install the Blackfyre Python library, you can use pip locally.
```bash
# cd to the folder that contains the setup.py file 
cd path/to/folder

# Install the Blackfyre Python library
pip install .
```

# Using  the Blackfyre Python Library
 Here is a snippet to load the binary context container (bcc) file and meta-data of the binary using the Blackfyre Python library
```python
from blackfyre.datatypes.contexts.vex.vexbinarycontext import VexBinaryContext

# Load the binary context container (bcc) file
TEST_BCC_FILE_PATH = "path/to/bcc/file"
vex_binary_context: VexBinaryContext = VexBinaryContext.load_from_file(TEST_BCC_FILE_PATH)

# Display basic meta-data about the binary

print(f"Binary Name: {vex_binary_context.name}")
print(f"Binary SHA256: {vex_binary_context.sha256_hash}")
print(f"Binary File Type: {vex_binary_context.file_type}")
print(f"Processor Type: {vex_binary_context.proc_type}")
print(f"Number of Functions: {len(vex_binary_context.function_context_dict)}")
print(f"Number of Strings: {len(vex_binary_context.string_refs)}")
print(f"Number of Import Functions: {len(vex_binary_context.import_symbols)}")
print(f"Number of Export Functions: {len(vex_binary_context.export_symbols)}")
print(f"Number of Defined Data: {len(vex_binary_context.defined_data_map)}")
print(f"Disassembly Type: {vex_binary_context.disassembler_type}")
print(f"Endianness: {vex_binary_context.endness}")


# Print the function names in the binary context container (bcc) file
print("\nFirst 5 Functions:")
for index, function_context in enumerate(vex_binary_context.function_contexts):
    print(f"="*100)
    print(f"  - Function Name: {function_context.name}")
    print(f"  - Function Start Address: {function_context.address}")
    print(f"  - Function End Address: {function_context.end_address}")
    print(f"  - Function Size: {function_context.size}")
    print(f"  - Function Number of Blocks: {len(function_context.basic_block_context_dict)}")
    print(f"  - Function Number of Callees: {len(function_context.callees)}")
    print(f"  - Function Number of Callers: {len(function_context.callers)}")
    print(f"  - Function Decompile Code: {function_context.decompiled_code[:120]}")
    print(f"=" * 100 + "\n")

    if index == 5:
        break

