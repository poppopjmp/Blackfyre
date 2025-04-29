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

## 5. Future Extensions

The following extensions are planned for future releases:

- **Vulnerability Database Integration**: Automatically detect known vulnerabilities
- **Enhanced VEX IR Analysis**: Improved data flow and symbolic execution
- **Machine Learning Integration**: Function similarity detection and binary classification
