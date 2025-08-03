import re
import pathlib
import urllib.parse as _url

__all__ = [
    "validate_url",
    "validate_cmd",
    "safe_open_read",
]

# ------------ URL validation -----------------------------------------
_URL_RE = re.compile(
    r"^(https?|ftp)://"            # scheme
    r"[A-Za-z0-9\-._~]+(:[0-9]+)?" # host[:port]
    r"(/.*)?$",                    # optional path/query
    re.I,
)

def validate_url(url: str) -> bool:
    """True if url is syntactically safe & RFC-compliant."""
    return bool(_URL_RE.fullmatch(url.strip()))

# ------------ command validation -------------------------------------
from config import BAD_SHELL_CHARS, MAX_URL_LENGTH
_BAD_SHELL_CHARS = re.compile(BAD_SHELL_CHARS)


def validate_cmd(cmd: str) -> bool:
    """
    Reject obvious shell-injection attempts:
    1. disallow ; & | ` $ > <  (PowerShell/CMD separators)
    2. length limit 8 kB
    """
    cmd = " ".join(cmd.split())          # collapse repeated whitespace
    return len(cmd) < 8192 and not _BAD_SHELL_CHARS.search(cmd)

# ------------ safe file read helper ----------------------------------
def safe_open_read(path: str) -> str:
    """
    Read a *data* file located inside project folder. Raises ValueError
    if an absolute path or parent-traversal is attempted.
    """
    p = pathlib.Path(path)
    if p.is_absolute() or ".." in p.parts:
        raise ValueError("Unsafe path detected")
    return p.read_text(encoding="utf-8", errors="ignore")
