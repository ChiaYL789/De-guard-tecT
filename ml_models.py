import joblib
import pandas as pd
from config import URL_MODEL_PATH, CMD_MODEL_PATH, SAFE_DOMAINS
from rules import cmd_rule_check 
from urllib.parse import urlparse
from nlp_features import augment


_url_model = None
_cmd_model = None


def load_url_model():
    """Load the URL classification pipeline (singleton)."""
    global _url_model
    if _url_model is None:
        _url_model = joblib.load(URL_MODEL_PATH)
    return _url_model


def load_cmd_model():
    """Load the CMD classification pipeline (singleton)."""
    global _cmd_model
    if _cmd_model is None:
        _cmd_model = joblib.load(CMD_MODEL_PATH)
    return _cmd_model


# ---------------------------------------------------------------------
# URL classification – simple 1-D list is fine
# ---------------------------------------------------------------------

def classify_url(url: str) -> str:
    """
    Classify a URL string using the pre-trained URL pipeline.
    Returns one of: 'Malicious', 'Suspicious', 'Legitimate'.
    """
    host = urlparse(url).hostname or ""
    if host.lower() in SAFE_DOMAINS:
         return "Legitimate"
    model = load_url_model()
    return model.predict([url])[0]


# ---------------------------------------------------------------------
# CMD classification – requires the full training schema (9 columns)
# ---------------------------------------------------------------------

_NUMERIC_COLS = [
    "Lolbin (0.05)", "Content (0.4)", "Frequency (0.2)",
    "Source (0.1)", "Network (0.1)", "Behavioural (0.1)",
    "History (0.05)", "Score"
]

def classify_cmd(cmd: str) -> str:
    """
    Apply fast regex rules first; if any hit, return 'Malicious'.
    Otherwise, enrich the command with NLP meta-tokens and classify.
    """
    from nlp_features import augment  # local import to avoid hard dependency at module load

    # Heuristic rule short-circuit (e.g., certutil, mshta patterns)
    if cmd_rule_check(cmd):
        return "Malicious"

    # NLP augmentation (adds tokens like LONGCMD, ENCODED, SUSPECT_VERB)
    enriched = augment(cmd)

    # ML prediction
    model = load_cmd_model()
    return model.predict([enriched])[0]
