# Binary Ninja plugin for Blackfyre
from binaryninja import PluginCommand
from .exporter import BlackfyreBinaryNinjaExporter

def export_to_bcc(bv):
    """Export the current Binary Ninja view to BCC format"""
    exporter = BlackfyreBinaryNinjaExporter(bv)
    exporter.export_to_bcc()

# Register the plugin command
PluginCommand.register(
    "Export to Blackfyre BCC",
    "Export binary analysis to Blackfyre Binary Context Container format",
    export_to_bcc
)
