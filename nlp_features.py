import re, spacy
_nlp = spacy.load("en_core_web_sm", disable=["ner", "lemmatizer"])

# verbs we care about in shell / PowerShell context
_SUSPECT_VERBS = {
    "download", "invoke", "execute", "exec", "inject",
    "encode", "decode", "upload", "spawn"
}

def meta_tokens(cmd: str) -> str:
    """
    Return a space-separated string of *meta* tokens that
    describe abnormal syntax patterns.
    """
    cmd = cmd.strip()
    flags = []

    if len(cmd) > 300:
        flags.append("LONGCMD")          # unusually long one-liner
    if "&&" in cmd or ";;" in cmd:
        flags.append("MULTI_DELIM")      # chained command separators
    if re.search(r'(?:-enc|base64)', cmd, re.I):
        flags.append("ENCODED")          # encoded payload hints
    if re.search(r'\b(0x[0-9a-f]{2,})\b', cmd, re.I):
        flags.append("HEX_BLOB")         # long hex constants

    # POS-tag verbs
    doc = _nlp(cmd)
    verbs = {t.lemma_.lower() for t in doc if t.pos_ == "VERB"}
    if verbs & _SUSPECT_VERBS:
        flags.append("SUSPECT_VERB")

    return " ".join(flags)

def augment(cmd: str) -> str:
    """Append meta-tokens to the original string (used by model & CLI)."""
    return f"{cmd} {meta_tokens(cmd)}"
