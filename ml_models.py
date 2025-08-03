import joblib
import pandas as pd  # (not used directly; kept for compatibility)
from config import SAFE_DOMAINS
from rules import cmd_rule_check
from urllib.parse import urlparse
from security_utils import safe_open_binary, sanitize_text

_url_model = None
_cmd_model = None


def load_url_model():
    """Load the URL classification pipeline (singleton)."""
    global _url_model
    if _url_model is None:
        try:
            with safe_open_binary("models/url_classifier.pkl") as fh:
                _url_model = joblib.load(fh)
        except FileNotFoundError:
            raise RuntimeError("URL model not found. Run training_v3.py to generate it.")
    return _url_model


def load_cmd_model():
    """Load the CMD classification pipeline (singleton)."""
    global _cmd_model
    if _cmd_model is None:
        try:
            with safe_open_binary("models/cmd_classifier.pkl") as fh:
                _cmd_model = joblib.load(fh)
        except FileNotFoundError:
            raise RuntimeError("CMD model not found. Run training_v3.py to generate it.")
    return _cmd_model


# ---------------------------------------------------------------------
# URL classification
# ---------------------------------------------------------------------

def _is_trusted_host(host: str) -> bool:
    """
    Allow-list policy: host must be exactly a trusted domain or a subdomain of it.
    E.g., docs.python.org -> trusted because it endswith ".python.org".
    """
    h = (host or "").lower()
    for d in SAFE_DOMAINS:
        if h == d or h.endswith("." + d):
            return True
    return False


def _is_deceptive_brand_in_subdomain(host: str) -> bool:
    """
    Detect deceptive use of trusted brands when they are NOT the registrable domain
    or its subdomain. Example:
        accounts.google.com.security-check.help  -> deceptive (contains 'google.com'
        but actual domain is 'security-check.help').
    """
    h = (host or "").lower()
    for d in SAFE_DOMAINS:
        if d in h and not (h == d or h.endswith("." + d)):
            return True
    return False


def classify_url(url: str) -> str:
    """
    Classify a URL string using the pre-trained URL pipeline.
    Returns one of: 'Malicious', 'Suspicious', 'Legitimate'.
    """
    url = sanitize_text(url)
    host = (urlparse(url).hostname or "").lower()

    # Runtime policy layer
    if _is_trusted_host(host):
        return "Legitimate"
    if _is_deceptive_brand_in_subdomain(host):
        return "Malicious"

    # ML model
    model = load_url_model()
    return model.predict([url])[0]


# ---------------------------------------------------------------------
# CMD classification
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
    # Heuristic rule short-circuit (e.g., certutil, mshta patterns)
    if cmd_rule_check(cmd):
        return "Malicious"

    # NLP augmentation (adds tokens like LONGCMD, ENCODED, SUSPECT_VERB)
    from nlp_features import augment  # local import to avoid hard dependency at module load
    enriched = augment(cmd)

    # ML prediction
    model = load_cmd_model()
    return model.predict([enriched])[0]
