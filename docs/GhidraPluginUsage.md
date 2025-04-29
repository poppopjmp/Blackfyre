# Blackfyre GenerateBinaryContext Ghidra Plugin User Guide

This guide explains how to use the GenerateBinaryContext Ghidra plugin to extract binary analysis information.

## Installation

1. Ensure you have Ghidra installed on your system
2. Copy the `Blackfyre` directory to your Ghidra scripts directory (typically `<GHIDRA_INSTALL_DIR>/Ghidra/Features/Base/ghidra_scripts/`)
3. Restart Ghidra if it's already running

## Dependencies

The plugin requires the following package structure to be present:

```
blackfyre/
├── datatypes/
│   ├── FileType.java
│   └── ghidra/
│       ├── GhidraBinaryContext.java
│       ├── GhidraFunctionContext.java
│       └── GhidraPEBinaryContext.java
└── GenerateBinaryContext.java
```

Make sure all these files are properly included in your project.

## Using the Plugin Interactively

1. **Open Ghidra** and load your target binary file
2. **Wait for analysis** to complete (or at least the important parts)
3. **Open Script Manager**:
   - Press `Ctrl+Shift+S` or
   - Navigate to `Window > Script Manager`
4. **Find the Script**:
   - In the script manager, navigate to `Blackfyre` category
   - Locate `GenerateBinaryContext.java`
5. **Run the Script**:
   - Double-click the script name or
   - Select it and click the "Run" button
6. **Provide Information** in the dialog prompts:
   - Select an output directory to save the binary context
   - Choose whether to include the raw binary data
   - Choose whether to include decompiled code
   - If including decompiled code:
     - Set a timeout value (30 seconds recommended)
     - Optionally specify a function filter regex pattern
   - Choose whether to include extended metadata (symbols, strings, imports/exports)
7. **Wait for Processing** to complete
8. **Verify Output** in your chosen directory

## Using the Plugin in Headless Mode

Headless mode allows you to process binaries without the Ghidra GUI, useful for batch processing or automation.

### Basic Command Structure:

```
analyzeHeadless <GHIDRA_PROJECT_DIR> <PROJECT_NAME> 
  -import <BINARY_PATH> 
  -postScript GenerateBinaryContext.java <OUTPUT_DIR> <INCLUDE_RAW> <INCLUDE_DECOMPILED> [<TIMEOUT> [<FILTER> [<EXTENDED_METADATA>]]]
  -scriptPath <PATH_TO_SCRIPTS>
```

### Example Commands:

1. **Basic usage with default options**:
```
analyzeHeadless /tmp/GhidraProjects TestProject 
  -import /path/to/binary.exe 
  -postScript GenerateBinaryContext.java "/output/directory" true true 
  -scriptPath /path/to/ghidra_scripts
```

2. **Advanced usage with all options**:
```
analyzeHeadless /tmp/GhidraProjects TestProject 
  -import /path/to/binary.exe 
  -postScript GenerateBinaryContext.java "/output/directory" true true 60 "main|init.*" true 
  -scriptPath /path/to/ghidra_scripts
```

### Parameter Description:

1. `<OUTPUT_DIR>`: Directory where the binary context will be saved
2. `<INCLUDE_RAW>`: Boolean (`true`/`false`) to include raw binary data
3. `<INCLUDE_DECOMPILED>`: Boolean (`true`/`false`) to include decompiled code
4. `<TIMEOUT>`: (Optional) Timeout in seconds for decompilation (default: 30)
5. `<FILTER>`: (Optional) Regex pattern to filter functions (default: ".*" - all functions)
6. `<EXTENDED_METADATA>`: (Optional) Boolean to include extended metadata (default: false)

## Understanding the Output

The plugin creates a binary context file with the analysis results. This file contains:

1. **Basic Information**:
   - Binary name and path
   - SHA-256 hash
   - File type and architecture
   - Entry point
   
2. **Function Data** (if decompiled code is included):
   - Function names and addresses
   - Decompiled C code for each function (filtered by regex if specified)
   
3. **Raw Binary** (if included):
   - The complete binary file data
4. **Extended Metadata** (if included):
   - Symbol information
   - String references
   - Import/Export tables
   - Other format-specific metadata

## Troubleshooting

1. **Script not found in Ghidra**:
   - Verify the script is in the correct directory
   - Check that the script path is included in Ghidra's script directories
2. **Analysis timeout errors**:
   - Increase the timeout value for complex functions
   - Use a more specific function filter to process only necessary functions
3. **Memory issues**:
   - Process large binaries in chunks using function filters
   - Increase Java heap size for Ghidra
4. **File format errors**:
   - Ensure the binary is a supported format (PE, ELF, Mach-O)
   - For uncommon formats, the generic binary context will be used

## Advanced Usage

### Function Filtering Examples:

- **Main function only**: `main`
- **Initialization functions**: `init.*`
- **Multiple specific functions**: `(main|start|_DllMainCRTStartup)`
- **Functions with specific prefix**: `sub_.*`

### Batch Processing:

Create a shell script to process multiple binaries in sequence:

```bash
#!/bin/bash
GHIDRA_PATH="/path/to/ghidra"
SCRIPT_PATH="/path/to/scripts"
OUTPUT_DIR="/output/directory"

for binary in /path/to/binaries/*.exe; do
  $GHIDRA_PATH/support/analyzeHeadless /tmp/GhidraProjects TestProject \
    -import "$binary" \
    -postScript GenerateBinaryContext.java "$OUTPUT_DIR" true true 30 ".*" true \
    -scriptPath "$SCRIPT_PATH" \
    -deleteProject
done
```
