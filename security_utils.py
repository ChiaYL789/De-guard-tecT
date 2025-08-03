# security_utils.py
import io, os, re, unicodedata, pathlib
from typing import Optional
from urllib.parse import urlsplit
from config import (
    PROJECT_ROOT, SAFE_READ_ROOTS, ALLOWED_READ_EXTS, MAX_FILE_BYTES,
    SAFE_DOMAINS, BLOCKED_TLDS, MAX_URL_LENGTH, ALLOWED_SCHEMES,
    BAD_SHELL_CHARS, MAX_CMD_LENGTH
)

# ---------- Sanitization -----------------------------------------------------
_ZW = {"\u200b", "\u200c", "\u200d", "\ufeff"}  # zero-width chars

def sanitize_text(s: str) -> str:
    """Unicode-normalize, drop control/zero-width chars, collapse whitespace."""
    if s is None:
        return ""
    s = unicodedata.normalize("NFKC", s)
    s = "".join(ch for ch in s if ch not in _ZW and unicodedata.category(ch)[0] != "C")
    s = " ".join(s.split())
    return s.strip()

# ---------- URL validation ---------------------------------------------------
def validate_url(url: str) -> bool:
    """Strict-ish URL validation with scheme/host/length checks."""
    url = sanitize_text(url)
    if not url or len(url) > MAX_URL_LENGTH:
        return False

    parts = urlsplit(url)
    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        return False
    if not parts.netloc:
        return False

    host = parts.hostname or ""
    # Optional: shallow TLD block for demo (keep list tiny)
    if "." in host:
        tld = host.rsplit(".", 1)[-1].lower()
        if tld in BLOCKED_TLDS:
            return False
    return True

# ---------- Command validation ----------------------------------------------
def validate_cmd(cmd: str) -> bool:
    """Reject unsafe metacharacters and overly long commands."""
    cmd = sanitize_text(cmd)
    if not cmd or len(cmd) > MAX_CMD_LENGTH:
        return False
    if BAD_SHELL_CHARS.search(cmd):
        return False
    return True

# ---------- Secure file handling --------------------------------------------
class UnsafePathError(Exception): ...
class DisallowedExtensionError(Exception): ...
class FileTooLargeError(Exception): ...

def _ensure_safe_read_path(path: str | os.PathLike) -> pathlib.Path:
    p = pathlib.Path(path)
    # Block absolute paths and traversal
    if p.is_absolute():
        raise UnsafePathError("Absolute paths are not allowed")
    if ".." in p.parts:
        raise UnsafePathError("Path traversal is not allowed")

    # Resolve and ensure within allowed roots
    rp = (PROJECT_ROOT / p).resolve()
    if not any(str(rp).startswith(str(root.resolve()) + os.sep) for root in SAFE_READ_ROOTS):
        raise UnsafePathError(f"Read denied outside safe roots: {rp}")

    # Block symlinks in the resolved chain (best-effort)
    try:
        for parent in [rp] + list(rp.parents):
            if parent.is_symlink():
                raise UnsafePathError("Symlinked paths are not allowed")
    except Exception:
        pass

    # Extension allow-list
    if rp.suffix.lower() not in ALLOWED_READ_EXTS:
        raise DisallowedExtensionError(f"Extension not allowed: {rp.suffix}")
    # Size check
    if rp.exists() and rp.stat().st_size > MAX_FILE_BYTES:
        raise FileTooLargeError(f"File too large: {rp.stat().st_size} bytes")
    return rp

def safe_open_read(path: str, encoding: str = "utf-8") -> str:
    rp = _ensure_safe_read_path(path)
    with rp.open("r", encoding=encoding, errors="replace") as fh:
        return fh.read()

def safe_open_binary(path: str):
    rp = _ensure_safe_read_path(path)
    return rp.open("rb")
