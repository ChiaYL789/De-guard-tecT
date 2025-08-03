# --- Security configuration -------------------------------------------------
from pathlib import Path
import re

# Project root (adjust if you run outside the repo)
PROJECT_ROOT = Path(__file__).resolve().parent

# Backward-compat alias for older modules (e.g., logger.py)
BASE_DIR = PROJECT_ROOT

# Model paths
MODEL_DIR = PROJECT_ROOT / "models"
URL_MODEL_PATH = MODEL_DIR / "url_classifier.pkl"
CMD_MODEL_PATH = MODEL_DIR / "cmd_classifier.pkl"

# File I/O policy
SAFE_READ_ROOTS = {
    PROJECT_ROOT / "dataset",
    PROJECT_ROOT / "models",
}
ALLOWED_READ_EXTS = {".csv", ".xlsx", ".json", ".pkl"}
MAX_FILE_BYTES = 128 * 1024 * 1024  # 128 MB

# URL policy
SAFE_DOMAINS = {
    "github.com", "google.com", "microsoft.com", "youtube.com", "docs.python.org"
}
BLOCKED_TLDS = {"ru", "zip", "mov"}  # keep tiny; demo-oriented
MAX_URL_LENGTH = 2048
ALLOWED_SCHEMES = {"http", "https", "ftp"}

# Command validation
BAD_SHELL_CHARS = re.compile(r"[;&|`$><\n\r^%]")
MAX_CMD_LENGTH = 8192
