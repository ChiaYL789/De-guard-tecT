import logging
import os
from logging.handlers import RotatingFileHandler
from config import BASE_DIR

_LOG_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(_LOG_DIR, exist_ok=True)

_LOG_PATH = os.path.join(_LOG_DIR, "malcommandguard.log")
_FMT = "[%(asctime)s] %(levelname)s: %(message)s"


def get_logger(name: str = "malcommandguard") -> logging.Logger:
    """Return a singleton logger configured for console + file."""
    logger = logging.getLogger(name)

    if logger.handlers:         
        return logger

    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter(_FMT)

    # ── Console ────────────────────────────────────────────────────
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    # ── Rotating File ──────────────────────────────────────────────
    fh: RotatingFileHandler = RotatingFileHandler(
        _LOG_PATH, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    # Prevent propagation to root logger (avoids duplicate lines)
    logger.propagate = False
    return logger
