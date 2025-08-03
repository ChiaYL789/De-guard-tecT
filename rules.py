import re
from typing import List, Tuple, Pattern

# --------------------------------------------------------------------
# Regex patterns for known malicious behaviours (compiled once)
# --------------------------------------------------------------------
# NOTE: We intentionally avoid a generic "any http(s) URL" rule because
# many benign admin commands include documentation links or API calls.
# Focus on download/execute, encoded payloads, LOLBIN abuse, persistence.

_RAW_RULES: List[Tuple[str, str]] = [
    # PowerShell encoded / obfuscated payloads
    ("PowerShell Encoded Payload",
     r"\bpowershell(?:\.exe)?\b[^\n]*?(?:-enc(?:odedcommand)?|\bFromBase64String\b)"),

    # IEX download-execute one-liner via iwr/wget
    ("IEX Download-Execute",
     r"\b(?:iwr|invoke-webrequest|wget)\b[^\n|]*\|\s*iex\b"),

    # certutil used to fetch from URL (classic LOLBIN)
    ("Certutil Download",
     r"\bcertutil(?:\.exe)?\b[^\n]*?(?:-urlcache|-split|-f)[^\n]*https?://"),

    # BITSAdmin pulling from URL
    ("BITSAdmin Download",
     r"\bbitsadmin(?:\.exe)?\b[^\n]*\btransfer\b[^\n]*https?://"),

    # mshta with inline JavaScript [T1218]
    ("MSHTA JavaScript Eval",
     r"\bmshta(?:\.exe)?\b[^\n]*javascript:"),

    # rundll32 URL handler abuse to open remote URL
    ("Rundll32 URL Handler",
     r"\brundll32(?:\.exe)?\b[^\n]*\burl\.dll,FileProtocolHandler\b[^\n]*https?://"),

    # curl/wget piped directly into a shell (Command Injection)
    ("Curl/Wget Pipe to Shell",
     r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:bash|sh)\b"),

    # curl/wget explicitly downloading PS1 or EXE
    ("Curl/Wget Download Script/Binary",
     r"\b(?:curl|wget)\b[^\n]*https?://[^\s\"']+\.(?:ps1|exe)\b"),

    # Invoke-WebRequest saving to file (generic downloader)
    ("Invoke-WebRequest OutFile",
     r"\bInvoke-WebRequest\b[^\n]*\b-OutFile\b"),

    # Writing an EXE into Temp folders (common drop location)
    ("Temp EXE Drop",
     r"(?:\\|/)(?:AppData\\Local\\Temp|Temp)[^\\/\n]*\.exe\b"),
]

# Pre-compile with IGNORECASE to speed up matching
RULE_PATTERNS: List[Tuple[str, Pattern[str]]] = [
    (name, re.compile(rx, re.IGNORECASE)) for name, rx in _RAW_RULES
]

# --------------------------------------------------------------------
# Public helpers
# --------------------------------------------------------------------
def apply_rules(command: str) -> List[str]:
    """
    Return a list of rule names that match the supplied string.
    """
    if not command:
        return []
    hits = [name for name, pat in RULE_PATTERNS if pat.search(command)]
    return hits


def cmd_rule_check(command: str) -> bool:
    """
    Quick boolean convenience: True if ANY rule matches.
    """
    return bool(apply_rules(command))
