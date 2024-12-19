@echo off

REM ===============================
REM USER CONFIGURATION SECTION
REM ===============================
REM Specify the full path to your Ghidra installation
set GHIDRA_PATH=C:\ghidra_11.2.1_PUBLIC

REM Specify other parameters
set PROJECT_DIR=C:\tmp
set PROJECT_NAME=my_headless
set BINARY_PATH=..\..\test\bison_arm_9409117ee68a2d75643bb0e0a15c71ab52d4e90fa066e419b1715e029bcdc3dd
set OUTPUT_PATH=.
set INCLUDE_RAW_BINARY=true
set INCLUDE_DECOMPILED_CODE=true
set DECOMPILE_TIMEOUT=30

REM ===============================
REM END OF USER CONFIGURATION
REM ===============================

REM Validate the Ghidra path
if not exist "%GHIDRA_PATH%\support\analyzeHeadless.bat" (
    echo Error: Invalid Ghidra path or analyzeHeadless.bat not found at "%GHIDRA_PATH%\support\analyzeHeadless.bat".
    exit /b 1
)

REM Run the Ghidra analyzeHeadless command
"%GHIDRA_PATH%\support\analyzeHeadless.bat" ^
    "%PROJECT_DIR%" ^
    "%PROJECT_NAME%" ^
    -import "%BINARY_PATH%" ^
    -deleteProject ^
    -postScript GenerateBinaryContext.java "%OUTPUT_PATH%" "%INCLUDE_RAW_BINARY%" "%INCLUDE_DECOMPILED_CODE%" "%DECOMPILE_TIMEOUT%"
