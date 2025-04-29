# Blackfyre Ghidra Scripts

This directory contains Ghidra scripts for generating binary context containers for use with Blackfyre.

## GenerateBinaryContext.java

A Ghidra script that analyzes a binary and generates a binary context container file.

### Quick Start

1. Load your binary into Ghidra and run analysis
2. Run the GenerateBinaryContext script from Script Manager
3. Follow the prompts to generate your binary context file

For detailed instructions, see the comprehensive documentation in `/docs/GhidraPluginUsage.md`.

### Command-line Usage

```
analyzeHeadless <PROJECT_DIR> <PROJECT_NAME> -import <BINARY_PATH> -postScript GenerateBinaryContext.java <OUTPUT_DIR> <INCLUDE_RAW> <INCLUDE_DECOMPILED> [<TIMEOUT> [<FILTER> [<EXTENDED_METADATA>]]]
```

Parameters:
- `<OUTPUT_DIR>`: Directory to save the binary context
- `<INCLUDE_RAW>`: Include raw binary data (true/false)
- `<INCLUDE_DECOMPILED>`: Include decompiled code (true/false)
- `<TIMEOUT>`: (Optional) Decompilation timeout in seconds (default: 30)
- `<FILTER>`: (Optional) Function filter regex (default: ".*")
- `<EXTENDED_METADATA>`: (Optional) Include extended metadata (true/false)
