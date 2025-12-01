import ctypes
import sys
from importlib.util import find_spec


def should_default_ccid() -> bool:
    if find_spec("smartcard") is None:
        return False

    if sys.platform != "win32" and sys.platform != "cygwin":
        # Linux or MacOS don't need admin to access with CTAPHID
        return False

    try:
        if ctypes.windll.shell32.IsUserAnAdmin():
            return False
        else:
            return True
    except Exception:
        return False
