#!/bin/bash

# Define paths - modify these according to your system
GHIDRA_PATH="/usr/share/ghidra"  # Typical path in Kali
PROJECT_DIR="/home/user/ghidra_projects"
PROJECT_NAME="BlackfyreAnalysis"
INPUT_FILE="/home/user/ghidra/binary"
OUTPUT_DIR="/home/user/ghidra/output"

# Detect Ghidra version or use provided version
if [ -f "${GHIDRA_PATH}/Ghidra/application.properties" ]; then
    GHIDRA_VERSION=$(grep "application.version=" "${GHIDRA_PATH}/Ghidra/application.properties" | cut -d'=' -f2)
else
    # Default to common version if can't detect
    GHIDRA_VERSION="10.3"
    echo "Warning: Could not detect Ghidra version, using default ${GHIDRA_VERSION}"
fi

# Set up plugin path with detected version
BLACKFYRE_PLUGIN_PATH="${HOME}/.ghidra/.ghidra_${GHIDRA_VERSION}/Extensions/Blackfyre"
BLACKFYRE_LIB_PATH="${BLACKFYRE_PLUGIN_PATH}/lib"

# Check plugin directory structure
if [ ! -d "${BLACKFYRE_PLUGIN_PATH}" ]; then
    echo "Error: Blackfyre plugin directory not found at ${BLACKFYRE_PLUGIN_PATH}"
    echo "Please install the Blackfyre plugin first."
    exit 1
fi

# Check and handle lib directory
if [ ! -d "${BLACKFYRE_LIB_PATH}" ]; then
    echo "Warning: Lib directory not found at ${BLACKFYRE_LIB_PATH}"
    echo "Checking for JAR files directly in plugin directory..."
    
    # Look for JAR files in the main plugin directory
    JAR_COUNT=$(find "${BLACKFYRE_PLUGIN_PATH}" -maxdepth 1 -name "*.jar" | wc -l)
    
    if [ "$JAR_COUNT" -gt 0 ]; then
        echo "Found JAR files in main plugin directory, using that instead of lib folder"
        BLACKFYRE_LIB_PATH="${BLACKFYRE_PLUGIN_PATH}"
    else
        echo "No JAR files found in plugin directory. Creating lib directory..."
        mkdir -p "${BLACKFYRE_LIB_PATH}"
        echo "Please copy Blackfyre JAR files to: ${BLACKFYRE_LIB_PATH}"
        echo "You can do this with: cp /path/to/blackfyre-*.jar ${BLACKFYRE_LIB_PATH}/"
        
        # Continue with warning
        echo "Continuing without JAR files, but expect class not found errors"
    fi
fi

# Make the script executable
chmod +x "${GHIDRA_PATH}/support/analyzeHeadless"

# Create directory if it doesn't exist
mkdir -p "${OUTPUT_DIR}"

# Print debug info
echo "Using Ghidra version: ${GHIDRA_VERSION}"
echo "Blackfyre plugin path: ${BLACKFYRE_PLUGIN_PATH}"
echo "Using JAR files from: ${BLACKFYRE_LIB_PATH}"

# List JAR files being used
echo "Available JAR files:"
find "${BLACKFYRE_LIB_PATH}" -name "*.jar" | sort

# Run Ghidra in headless mode - with jar directories based on actual structure
GHIDRA_CMD="${GHIDRA_PATH}/support/analyzeHeadless"
GHIDRA_ARGS=("${PROJECT_DIR}" "${PROJECT_NAME}"
  -import "${INPUT_FILE}"
  -postScript GenerateBinaryContext.java "${OUTPUT_DIR}" true true 30
  -scriptPath "${BLACKFYRE_PLUGIN_PATH}/ghidra_scripts"
  -log "${OUTPUT_DIR}/ghidra_headless.log"
  -deleteProject
  -overwrite)

# Add jarlocation if JAR files exist
if [ -n "$(find "${BLACKFYRE_LIB_PATH}" -name "*.jar" 2>/dev/null)" ]; then
    GHIDRA_ARGS+=(-jarlocation "${BLACKFYRE_LIB_PATH}")
fi

# Execute the command
"${GHIDRA_CMD}" "${GHIDRA_ARGS[@]}"

# Check if the operation was successful
if [ $? -ne 0 ]; then
    echo "Error: Ghidra headless analysis failed. Check the log at ${OUTPUT_DIR}/ghidra_headless.log"
    exit 1
else
    echo "Analysis completed successfully. Output saved to ${OUTPUT_DIR}"
fi
