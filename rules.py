# rules.py
# --------------------------------------------------------------------
"""
Implements rule-based detection using compiled regex patterns.

Design:
- Keep patterns specific to clearly risky behaviours to avoid false positives.
- 'Benign patterns' short-circuit to benign before ML (e.g., schtasks /query).
- 'Malicious patterns' short-circuit to malicious (e.g., certutil download).
"""

import re
from typing import List, Tuple, Pattern

# ---------------- Benign short-circuit patterns ---------------------
_BENIGN_RAW: List[Tuple[str, str]] = [
    # SCHTASKS query-only (no create/change/delete/run flags present)
    # Benign short-circuit: SCHTASKS query-only (no create/change/delete/run)
    ("SCHTASKS Query",
    r"\bschtasks(?:\.exe)?\b(?!.*/(?:create|change|delete|run)\b).*?/(?:query|q)\b"),


]

# ---------------- Malicious fast-path patterns ----------------------
_RAW_RULES: List[Tuple[str, str]] = [
    # PowerShell encoded payload
    ("PowerShell Encoded Payload",
     r"\bpowershell(?:\.exe)?\b[^\n]*?(?:-enc(?:odedcommand)?|\bFromBase64String\b)"),

    # iwr/wget → IEX
    ("IEX Download-Execute",
     r"\b(?:iwr|invoke-webrequest|wget)\b[^\n|]*\|\s*iex\b"),

    # certutil download
    ("Certutil Download",
     r"\bcertutil(?:\.exe)?\b[^\n]*?(?:-urlcache|-split|-f)[^\n]*https?://"),

    # BITSAdmin pulling from URL
    ("BITSAdmin Download",
     r"\bbitsadmin(?:\.exe)?\b[^\n]*\btransfer\b[^\n]*https?://"),

    # mshta inline javascript
    ("MSHTA JavaScript Eval",
     r"\bmshta(?:\.exe)?\b[^\n]*javascript:"),

    # rundll32 URL handler abuse
    ("Rundll32 URL Handler",
     r"\brundll32(?:\.exe)?\b[^\n]*\burl\.dll,FileProtocolHandler\b[^\n]*https?://"),

    # curl/wget download of script or EXE
    ("Curl/Wget Download Script/Binary",
     r"\b(?:curl|wget)\b[^\n]*https?://[^\s\"']+\.(?:ps1|exe)\b"),

    # Invoke-WebRequest saving to file
    ("Invoke-WebRequest/iwr OutFile",
     r"\b(?:Invoke-WebRequest|iwr)\b[^\n]*\s-?OutFile\b"),

    # Drop EXE into Temp
    ("Temp EXE Drop",
     r"(?:\\|/)(?:AppData\\Local\\Temp|Temp)[^\\/\n]*\.exe\b"),

    # Regsvr32 remote scriptlet (optional technique)
    ("Regsvr32 Remote Scriptlet",
     r"\bregsvr32(?:\.exe)?\b[^\n]*\b/i:https?://[^\s]+[^\n]*\bscrobj\.dll\b"),

    # Malicious: SCHTASKS create/change/delete/run
    ("SCHTASKS Create/Change/Delete/Run",
    r"\bschtasks(?:\.exe)?\b.*/(?:create|change|delete|run)\b"),

]

# ---------------- Compile patterns ---------------------------------
BENIGN_PATTERNS: List[Tuple[str, Pattern[str]]] = [
    (name, re.compile(rx, re.IGNORECASE)) for name, rx in _BENIGN_RAW
]
RULE_PATTERNS: List[Tuple[str, Pattern[str]]] = [
    (name, re.compile(rx, re.IGNORECASE)) for name, rx in _RAW_RULES
]

# ---------------- Public helpers -----------------------------------
def apply_benign_rules(text: str) -> List[str]:
    """Return benign rule names that match; used to short-circuit as 'benign'."""
    if not text:
        return []
    return [name for name, pat in BENIGN_PATTERNS if pat.search(text)]

def apply_rules(text: str) -> List[str]:
    """Return malicious rule names that match; used to short-circuit as 'Malicious'."""
    if not text:
        return []
    return [name for name, pat in RULE_PATTERNS if pat.search(text)]

def cmd_rule_check(text: str) -> bool:
    """Convenience boolean: any malicious rule hits?"""
    return bool(apply_rules(text))
