# Blackfyre IDA Pro Plugin

This plugin allows exporting IDA Pro analysis data to the Blackfyre Binary Context Container (BCC) format for further analysis with the Blackfyre framework.

## Installation

1. Copy the `blackfyre_ida.py` file to your IDA plugins directory:
   - Windows: `%APPDATA%\Hex-Rays\IDA Pro\plugins`
   - Linux: `~/.idapro/plugins`
   - macOS: `~/Library/Application Support/IDA Pro/plugins`

2. Make sure the Blackfyre Python library is installed and accessible from your IDA Python environment:
   ```
   pip install -e /path/to/blackfyre/src/python
   ```

## Usage

1. Open a binary in IDA Pro and wait for the initial analysis to complete
2. Press `Ctrl+Alt+B` or go to `Edit > Plugins > Blackfyre BCC Export`
3. Choose the output location for the BCC file
4. Choose whether to include the raw binary in the BCC file

The plugin will export:
- Binary metadata (name, hash, architecture, file type)
- Functions and basic blocks
- Strings
- Import and export symbols
- Call graph information (caller to callee relationships)

## Notes

- The plugin requires IDA Pro 7.0 or later
- For full decompilation support, the Hex-Rays Decompiler is recommended
- Large binaries may take some time to export, especially when including decompiled code

## Troubleshooting

If you encounter issues:
1. Check the output window for error messages
2. Verify that the Blackfyre Python library is correctly installed
3. Ensure you have sufficient permissions to write to the output directory

For detailed troubleshooting and more information, see the [Blackfyre documentation](https://github.com/jonescyber-ai/Blackfyre).
