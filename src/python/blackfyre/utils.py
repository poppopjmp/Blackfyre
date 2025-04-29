import errno
import logging
import os
import struct

from blackfyre.common import MessageType, LOG_DIR

logger = logging.getLogger("BlackfyreUtil")
logging.basicConfig(level=logging.INFO)
logger.setLevel(logging.INFO)


def get_message_type(data):
    """Extract the message type from binary data."""
    try:
        data = struct.unpack("B", data)[0]
        message_type = MessageType(data)
        return message_type
    except struct.error as e:
        logger.error(f"Failed to unpack message type: {e}")
        raise


def get_message_size(data):
    """Extract the message size from binary data."""
    try:
        message_size = struct.unpack(">I", data)[0]
        return message_size
    except struct.error as e:
        logger.error(f"Failed to unpack message size: {e}")
        raise


def mkdir_p(path):
    """Create a directory and handle existing directories gracefully."""
    try:
        os.makedirs(path)
    except OSError as exc:  # Python >2.5
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            logger.error(f"Failed to create directory {path}: {exc}")
            raise


def setup_custom_logger(name):
    """Set up a custom logger with a file handler."""
    mkdir_p(LOG_DIR)

    formatter = logging.Formatter(fmt='%(asctime)s %(levelname)-8s %(message)s',
                                  datefmt='%Y-%m-%d %H:%M:%S')
    handler = logging.FileHandler('{}.log'.format(os.path.join(LOG_DIR, name)), mode='w')
    handler.setFormatter(formatter)
    handler.setLevel(logging.INFO)
    my_logger = logging.getLogger(name)
    logging.basicConfig(level=logging.INFO)
    my_logger.setLevel(logging.INFO)
    my_logger.addHandler(handler)
    return my_logger


def read_binary_file(filepath):
    """Read binary data from a file."""
    try:
        with open(filepath, "rb") as f:
            data = f.read()
        logger.info(f"Successfully read binary file: {filepath}")
        return data
    except FileNotFoundError:
        logger.error(f"File not found: {filepath}")
        raise
    except IOError as e:
        logger.error(f"Error reading file {filepath}: {e}")
        raise