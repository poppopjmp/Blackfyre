# Blackfyre Codebase Structure Documentation

## Overview

Blackfyre is an open-source platform for standardizing and streamlining binary analysis. It consists of two main components:

1. **Disassembler Plugins** - Extract structured data from binaries into the Binary Context Container (BCC) format.
2. **Python Library** - Provides APIs for analyzing the extracted data.

## Repository Structure
```
Blackfyre/
├── src/
│   ├── ghidra/                - Ghidra plugin implementation
│   │   ├── ghidra_scripts/    - Ghidra scripts for analysis
│   │   └── java/              - Core Java data types and extraction logic
│   ├── python/                - Python library implementation
│   │   └── blackfyre/
│   │       ├── datatypes/     - Python data types and parsers
│   │       ├── ml/            - Machine learning modules
│   │       ├── visualization/ - Visualization components
│   │       └── cli.py         - Command-line interface
│   └── protos/                - Protocol Buffer definitions
├── examples/                  - Example scripts showing API usage
└── test/                      - Test binaries and data
```

## Core Components

### 1. Java/Ghidra Components

#### Key Classes

1. **`BinaryContext`** (`src/ghidra/java/blackfyre/datatypes/BinaryContext.java`)
   - Main container for binary analysis data.
   - Stores metadata, strings, imports, exports, and function information.
   - Responsible for serializing data to the BCC format.

2. **`FunctionContext`** (`src/ghidra/java/blackfyre/datatypes/FunctionContext.java`)
   - Represents a function within the binary.
   - Contains function name, addresses, basic blocks, and decompiled code.

3. **`BasicBlockContext`** (`src/ghidra/java/blackfyre/datatypes/BasicBlockContext.java`)
   - Represents a basic block (sequence of instructions).
   - Contains instructions and address ranges.

4. **`ImportSymbol`** (`src/ghidra/java/blackfyre/datatypes/ImportSymbol.java`)
   - Represents an imported function.
   - Contains import name, library name, and address.

5. **`Ghidra*`** classes (e.g., `GhidraBinaryContext`, `GhidraFunctionContext`)
   - Extend base classes with Ghidra-specific implementations.
   - Handle extraction of data from Ghidra's API.

#### Key Scripts

- **`GenerateBinaryContext.java`** (`src/ghidra/ghidra_scripts/GenerateBinaryContext.java`)
  - Main entry point for generating BCC files from Ghidra.
  - Can be run in GUI or headless mode.

### 2. Python Components

#### Key Modules

1. **`blackfyre.datatypes.contexts.binarycontext`**
   - Reads and parses BCC files.
   - Provides access to binary metadata and functions.

2. **`blackfyre.datatypes.contexts.vex`**
   - Integrates with PyVEX for architecture-agnostic analysis.
   - Lifts native instructions to VEX IR (Intermediate Representation).

3. **`blackfyre.ml`**
   - Machine learning modules for function similarity, classification, and vulnerability detection.

4. **`blackfyre.visualization`**
   - Visualization components for control flow graphs, call graphs, and binary comparisons.

### 3. Protocol Buffer Definitions

Located in `src/protos/`:

1. **`binary_context.proto`**
   - Defines the serialization format for the binary context.
   - Includes message definitions for binary metadata, imports, exports, etc.

2. **`function_context.proto`**
   - Defines the serialization format for function contexts.
   - Includes message definitions for function metadata, basic blocks, etc.

3. **`pe_header.proto`**
   - Defines the serialization format for PE header information.

## Data Flow

1. **Data Extraction**:
   - Ghidra plugin analyzes a binary and extracts metadata.
   - Data is organized into `BinaryContext`, `FunctionContext`, etc. objects.
   - Objects are serialized to Protocol Buffers and written to a BCC file.

2. **Data Analysis**:
   - Python library loads the BCC file.
   - Parses Protocol Buffer data into Python objects.
   - Provides APIs for analyzing functions, basic blocks, etc.
   - Optionally lifts to VEX IR for architecture-agnostic analysis.

## File Formats

### Binary Context Container (BCC)

The BCC is a compressed file containing:
- Binary Context Protocol Buffer message.
- Function Context Protocol Buffer messages.
- Optional raw binary data.
- SHA-256 hash for validation.

## Core Features

1. **Disassembler-Agnostic**: Works with Ghidra (and potentially IDA Pro and Binary Ninja).
2. **Architecture-Agnostic**: Uses PyVEX to support multiple architectures.
3. **Comprehensive Data Extraction**: Captures strings, imports, exports, functions, basic blocks, etc.
4. **Advanced Analysis APIs**: For exploring functions, basic blocks, and relationships.

## Architecture Support

Through PyVEX integration, Blackfyre supports analysis for:
- x86 (32-bit and 64-bit)
- ARM (32-bit and 64-bit)
- MIPS (32-bit and 64-bit)
- PowerPC (32-bit and 64-bit)

## Possible Extensions

### 1. Additional Disassembler Support

Blackfyre currently supports Ghidra as its primary disassembler platform. Extending support to other popular disassemblers would broaden its usefulness:

#### IDA Pro Plugin
- Implement a similar plugin architecture using IDA Pro's SDK.
- Extract binary data into the BCC format following the same protocol buffer structure.
- Example location: `src/idapro/Blackfyre/`.

#### Binary Ninja Plugin
- Leverage Binary Ninja's Python API to implement data extraction.
- Maintain compatibility with the existing BCC format.
- Example location: `src/binja/Blackfyre/`.

### 2. Advanced Analysis Features

#### Enhanced VEX IR Analysis

Blackfyre's Python library already leverages PyVEX for architecture-agnostic analysis. This could be extended with:

- **Data Flow Analysis**: Track how data moves through functions.
- **Symbolic Execution**: Implement lightweight symbolic execution using the VEX IR.
- **Control Flow Recovery**: Improve function boundary detection and indirect jump resolution.

#### Machine Learning Integration

Given Blackfyre's structured data output, integrating ML capabilities would be valuable:

- **Binary Similarity Detection**: Identify similar functions across different binaries.
- **Vulnerability Detection**: Train models to detect common vulnerability patterns.
- **Function Classification**: Automatically classify function purposes based on their behavior.
- **Anomaly Detection**: Identify suspicious code patterns.

### 3. Visualization Components

Adding visualization capabilities would enhance the analysis experience:

#### Control Flow Graphs
- Implement graph visualization for functions and their relationships.
- Support both static (SVG/PNG) and interactive (web-based) visualizations.

#### Call Graphs
- Visualize caller-callee relationships across the binary.
- Filter by library, import/export status, or other criteria.

#### Binary Comparison Views
- Side-by-side comparison of functions from different versions/binaries.
- Highlight differences in control flow, strings, and imports.

## Command Line Interface

Blackfyre provides a comprehensive CLI for binary analysis, organized into functional categories for better usability and maintainability. The CLI is implemented in `src/python/blackfyre/cli.py`.

### Command Categories

1. **Basic Analysis Commands**
   - `analyze` - Show binary statistics and list functions
   - `analyze_data_flow` - Analyze data flow in a function using VEX IR
   - `export_json` - Export binary data to JSON format for external analysis

2. **Diff & Comparison Commands**
   - `diff` - Compare two BCC files to identify changes
   - `compare_binaries` - Compare functions between two binaries to find similarities
   - `visual_diff` - Generate interactive visual comparison of two binaries

3. **Visualization Commands**
   - `visualize` - Visualize a function's control flow graph
   - `interactive` - Generate interactive web visualization of the binary

4. **Rule Generation Commands**
   - `generate_yara` - Generate YARA rules from a BCC file
   - `threat_analysis` - Analyze a binary for potential threats using threat intelligence

5. **Machine Learning Commands**
   - `extract_features` - Extract machine learning features from functions
   - `find_similar` - Find functions similar to a target function
   - `train_classifier` - Train a function classifier using labeled data
   - `classify_functions` - Classify functions in a binary using a trained model
   - `detect_vulnerabilities` - Detect potential vulnerabilities in a binary

6. **LLM Integration Commands**
   - `explain_function` - Explain a function using an LLM
   - `llm_vulnerability_scan` - Scan for vulnerabilities using LLM analysis
   - `analyze_comprehensive` - Run comprehensive LLM analysis on a binary
   - `summarize_binary` - Generate a natural language summary of the binary
   - `interactive_analysis` - Start an interactive chat session for binary analysis

### CLI Usage Examples

```bash
# Basic binary analysis
blackfyre analyze binary.bcc --stats --list-functions

# Generate YARA rules
blackfyre generate_yara binary.bcc -o rules.yar

# Compare two versions of a binary
blackfyre diff original.bcc updated.bcc -o diff_report.md

# Visualize a function's control flow graph
blackfyre visualize binary.bcc 0x401000 -o func_graph.png

# LLM-based function explanation
blackfyre explain_function binary.bcc 0x401000 --provider openai --model gpt-4

# Interactive analysis session with LLM
blackfyre interactive_analysis binary.bcc
```