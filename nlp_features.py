import re, spacy
_nlp = spacy.load("en_core_web_sm", disable=["ner", "lemmatizer"])

_SUSPECT_VERBS = {
    "download", "invoke", "execute", "exec", "inject",
    "encode", "decode", "upload", "spawn"
}

def meta_tokens(cmd: str) -> str:

    cmd = cmd.strip()
    flags = []

    if len(cmd) > 300:
        flags.append("LONGCMD")       
    if "&&" in cmd or ";;" in cmd:
        flags.append("MULTI_DELIM")      
    if re.search(r'(?:-enc|base64)', cmd, re.I):
        flags.append("ENCODED")          
    if re.search(r'\b(0x[0-9a-f]{2,})\b', cmd, re.I):
        flags.append("HEX_BLOB")        

    doc = _nlp(cmd)
    verbs = {t.lemma_.lower() for t in doc if t.pos_ == "VERB"}
    if verbs & _SUSPECT_VERBS:
        flags.append("SUSPECT_VERB")

    return " ".join(flags)

def augment(cmd: str) -> str:
    return f"{cmd} {meta_tokens(cmd)}"
