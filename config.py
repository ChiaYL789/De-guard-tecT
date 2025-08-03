import os

# Base directory of this script
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Directory where trained models are stored
MODEL_DIR = os.path.join(BASE_DIR, 'models')

# Paths to the serialized model files
URL_MODEL_PATH = os.path.join(MODEL_DIR, 'url_classifier.pkl')
CMD_MODEL_PATH = os.path.join(MODEL_DIR, 'cmd_classifier.pkl')

# --- security allow-lists -------------------------------------------------
SAFE_DOMAINS = {
    "github.com", "microsoft.com", "google.com", "youtube.com"
}

BAD_SHELL_CHARS = r"[;&|`$><\n\r^%]"   # newline, ^, % added
MAX_URL_LENGTH  = 2048                 # 2 kB safeguard

