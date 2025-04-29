"""Configuration settings for Blackfyre visualizations"""

# Color schemes
COLOR_SCHEMES = {
    "default": {
        "function": "#4285F4",  # Blue
        "import": "#EA4335",    # Red
        "export": "#FBBC05",    # Yellow
        "string": "#34A853",    # Green
        "basic_block": "#4285F4",
        "instruction": "#9AA0A6",
        "edge": "#80868B",
        "highlight": "#FF6D01",
        "background": "#FFFFFF"
    },
    "dark": {
        "function": "#8AB4F8",  # Light blue
        "import": "#F28B82",    # Light red
        "export": "#FDD663",    # Light yellow
        "string": "#81C995",    # Light green
        "basic_block": "#8AB4F8",
        "instruction": "#DADCE0",
        "edge": "#9AA0A6",
        "highlight": "#FFA95C",
        "background": "#202124"
    }
}

# Visualization defaults
DEFAULT_MAX_NODES = 200
DEFAULT_MAX_EDGES = 500
DEFAULT_NODE_SIZE = 8
DEFAULT_FONT_SIZE = 10
DEFAULT_COLOR_SCHEME = "default"
DEFAULT_PLOT_WIDTH = 12
DEFAULT_PLOT_HEIGHT = 8

# File paths
CACHE_DIR = None  # Will be set to ~/.cache/blackfyre/visualizations
