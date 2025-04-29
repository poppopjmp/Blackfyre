# Blackfyre Extensions

This document describes the extensions available for Blackfyre and how to use them.

## 1. Command Line Interface (CLI)

The Blackfyre CLI provides command-line access to Blackfyre's functionality for automation and scripting.

### Installation

After installing Blackfyre, the CLI is available as the `blackfyre` command.

### Usage

```bash
# Display help information
blackfyre --help

# Analyze a BCC file
blackfyre analyze path/to/file.bcc --stats --list-functions

# Generate YARA rules from a BCC file
blackfyre generate-yara path/to/file.bcc -o rules.yar

# Visualize a function's control flow graph
blackfyre visualize path/to/file.bcc 0x1000 -o function_cfg.png
```

## 2. Visualization Components

Blackfyre includes visualization tools for analyzing binary structure and behavior.

### Control Flow Graph

The `ControlFlowGraph` class can visualize the control flow of a function:

```python
from blackfyre.datatypes.contexts.binarycontext import BinaryContext
from blackfyre.visualization.cfg import ControlFlowGraph

# Load a binary context
binary_context = BinaryContext.load_from_file("example.bcc")

# Get a function by address
function = binary_context.function_context_dict[0x1000]

# Create and display the control flow graph
cfg = ControlFlowGraph(function)
cfg.plot(filename="function_cfg.png")
```

## 3. YARA Integration

Blackfyre can generate YARA rules from binary analysis to help with malware detection and binary matching.

### Generate Rules

```python
from blackfyre.datatypes.contexts.binarycontext import BinaryContext
from blackfyre.integrations.yara.rule_generator import YaraRuleGenerator

# Load binary context
binary_context = BinaryContext.load_from_file("example.bcc")

# Create the rule generator
generator = YaraRuleGenerator(binary_context)

# Generate YARA rules
rules = generator.generate_all_rules("output_rules.yar")
```

### Types of Rules Generated

- **String Rules**: Based on interesting strings found in the binary
- **Function Rules**: Based on distinctive byte patterns in functions
- **Import Rules**: Based on patterns of imported functions

## 4. Disassembler Plugins

### IDA Pro Plugin

Located in `src/idapro/Blackfyre/`, the IDA Pro plugin allows exporting IDA analysis to the BCC format.

Installation:
1. Copy files to your IDA plugins directory
2. Make sure the Blackfyre Python library is in your Python path

### Binary Ninja Plugin

Located in `src/binja/Blackfyre/`, the Binary Ninja plugin provides similar functionality for Binary Ninja users.

Installation:
1. Copy files to your Binary Ninja plugins directory
2. Install the Blackfyre Python library

### Ghidra Plugin in Headless Mode

Ghidra supports running the Blackfyre plugin in headless mode, which is useful for batch processing or automation.

#### Sample Script

```bash
#!/bin/bash

# Define paths - modify these according to your system
GHIDRA_PATH="/usr/share/ghidra"  # Typical path in Kali
PROJECT_DIR="/home/kali/ghidra_projects"
PROJECT_NAME="BlackfyreAnalysis"
INPUT_FILE="/path/to/your/binary"
OUTPUT_DIR="/path/to/output"
BLACKFYRE_PLUGIN_PATH="/home/kali/.ghidra/.ghidra_10.3/Extensions/Blackfyre"  # Update version as needed

# Make the script executable
chmod +x "${GHIDRA_PATH}/support/analyzeHeadless"

# Create directory if it doesn't exist
mkdir -p "${OUTPUT_DIR}"

# Run Ghidra in headless mode
"${GHIDRA_PATH}/support/analyzeHeadless" "${PROJECT_DIR}" "${PROJECT_NAME}" \
  -import "${INPUT_FILE}" \
  -postScript GenerateBinaryContext.java "${OUTPUT_DIR}" true true 30 \
  -scriptPath "${BLACKFYRE_PLUGIN_PATH}/ghidra_scripts" \
  -deleteProject \
  -overwrite
```

#### Script Parameters

The key parameters for the `GenerateBinaryContext.java` script are:

1. `"${OUTPUT_DIR}"` - Directory where the BCC file will be saved
2. `true` - Include raw binary data (set to `false` to exclude)
3. `true` - Include decompiled code (set to `false` to exclude)
4. `30` - Timeout in seconds for decompilation

#### Usage

1. Save the script to a file (e.g., `run_blackfyre_headless.sh`)
2. Make it executable: `chmod +x run_blackfyre_headless.sh`
3. Modify the paths to match your environment
4. Run the script: `./run_blackfyre_headless.sh`

## 5. Future Extensions

The following extensions are planned for future releases:

- **Vulnerability Database Integration**: Automatically detect known vulnerabilities
- **Enhanced VEX IR Analysis**: Improved data flow and symbolic execution
- **Machine Learning Integration**: Function similarity detection and binary classification
