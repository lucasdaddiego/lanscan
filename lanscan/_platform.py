"""Platform dispatch shared by the modules that shell out differently on Linux."""
import sys


def is_linux() -> bool:
    return sys.platform.startswith("linux")
