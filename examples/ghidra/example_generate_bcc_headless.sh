#!/bin/bash

# ===============================
# USER CONFIGURATION SECTION
# ===============================
# Specify the full path to your Ghidra installation
GHIDRA_PATH="/opt/ghidra_11.2.1_PUBLIC"

# Specify other parameters
PROJECT_DIR="/tmp"
PROJECT_NAME="my_headless"
BINARY_PATH="../../test/bison_arm_9409117ee68a2d75643bb0e0a15c71ab52d4e90fa066e419b1715e029bcdc3dd"
OUTPUT_PATH="."
INCLUDE_RAW_BINARY=true
INCLUDE_DECOMPILED_CODE=true
DECOMPILE_TIMEOUT=30

# ===============================
# END OF USER CONFIGURATION
# ===============================

# Validate the Ghidra path
if [ ! -x "$GHIDRA_PATH/support/analyzeHeadless" ]; then
    echo "Error: Invalid Ghidra path or analyzeHeadless not found at '$GHIDRA_PATH/support/analyzeHeadless'."
    exit 1
fi

# Run the Ghidra analyzeHeadless command
"$GHIDRA_PATH/support/analyzeHeadless" \
    "$PROJECT_DIR" \
    "$PROJECT_NAME" \
    -import "$BINARY_PATH" \
    -deleteProject \
    -postScript GenerateBinaryContext.java "$OUTPUT_PATH" "$INCLUDE_RAW_BINARY" "$INCLUDE_DECOMPILED_CODE" "$DECOMPILE_TIMEOUT"
