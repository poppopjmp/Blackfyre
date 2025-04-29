@echo off

:: Define paths - modify these according to your system
set GHIDRA_PATH=C:\path\to\ghidra
set PROJECT_DIR=C:\path\to\ghidra_projects
set PROJECT_NAME=BlackfyreAnalysis
set INPUT_FILE=C:\path\to\your\binary
set OUTPUT_DIR=C:\path\to\output
set BLACKFYRE_PLUGIN_PATH=C:\Users\username\AppData\Roaming\.ghidra\.ghidra_<version>\Extensions\Blackfyre

:: Create directory if it doesn't exist
mkdir "%OUTPUT_DIR%" 2>nul

:: Run Ghidra in headless mode
"%GHIDRA_PATH%\support\analyzeHeadless.bat" "%PROJECT_DIR%" "%PROJECT_NAME%" ^
  -import "%INPUT_FILE%" ^
  -postScript GenerateBinaryContext.java "%OUTPUT_DIR%" true true 30 ^
  -scriptPath "%BLACKFYRE_PLUGIN_PATH%\ghidra_scripts" ^
  -deleteProject ^
  -overwrite
