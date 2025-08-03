import re
from typing import List, Tuple, Pattern

# ---------------- Benign short-circuit patterns ---------------------
_BENIGN_RAW: List[Tuple[str, str]] = [
    
    ("SCHTASKS Query",
    r"\bschtasks(?:\.exe)?\b(?!.*/(?:create|change|delete|run)\b).*?/(?:query|q)\b"),
]

# ---------------- Malicious fast-path patterns ----------------------
_RAW_RULES: List[Tuple[str, str]] = [
    ("PowerShell Encoded Payload",
     r"\bpowershell(?:\.exe)?\b[^\n]*?(?:-enc(?:odedcommand)?|\bFromBase64String\b)"),

    ("IEX Download-Execute",
     r"\b(?:iwr|invoke-webrequest|wget)\b[^\n|]*\|\s*iex\b"),

    ("Certutil Download",
     r"\bcertutil(?:\.exe)?\b[^\n]*?(?:-urlcache|-split|-f)[^\n]*https?://"),

    ("BITSAdmin Download",
     r"\bbitsadmin(?:\.exe)?\b[^\n]*\btransfer\b[^\n]*https?://"),

    ("MSHTA JavaScript Eval",
     r"\bmshta(?:\.exe)?\b[^\n]*javascript:"),

    ("Rundll32 URL Handler",
     r"\brundll32(?:\.exe)?\b[^\n]*\burl\.dll,FileProtocolHandler\b[^\n]*https?://"),

    ("Curl/Wget Download Script/Binary",
     r"\b(?:curl|wget)\b[^\n]*https?://[^\s\"']+\.(?:ps1|exe)\b"),

    ("Invoke-WebRequest/iwr OutFile",
     r"\b(?:Invoke-WebRequest|iwr)\b[^\n]*\s-?OutFile\b"),

    ("Temp EXE Drop",
     r"(?:\\|/)(?:AppData\\Local\\Temp|Temp)[^\\/\n]*\.exe\b"),

    ("Regsvr32 Remote Scriptlet",
     r"\bregsvr32(?:\.exe)?\b[^\n]*\b/i:https?://[^\s]+[^\n]*\bscrobj\.dll\b"),

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
