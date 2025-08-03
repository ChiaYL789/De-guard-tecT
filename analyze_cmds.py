import pandas as pd
import re

# 1) load the sheet
from security_utils import safe_open_binary
with safe_open_binary('dataset/windows_cmd.xlsx') as fh:
    df = pd.read_excel(fh)

# 2) heuristics
lolbins = ['certutil','bitsadmin','powershell','at.exe','schtasks','mshta',
           'rundll32','regsvr32','wscript','cscript','wmic','msbuild','sc.exe']

def detect_lolbin(cmd): return any(b.lower() in cmd.lower() for b in lolbins)
def content_risk(cmd):
    if re.search(r'(http[s]?://|ftp://|\\\\)', cmd, re.IGNORECASE): return 1.0
    if re.search(r'\b(copy|move|rename|del)\b', cmd, re.IGNORECASE): return 0.5
    return 0.0
def frequency_risk(cmd): return 1.0 if re.search(r'\b(at|schtasks)\b', cmd, re.IGNORECASE) else 0.0
def source_risk(cmd):    return 1.0 if re.search(r'(http[s]?://|\\\\)', cmd, re.IGNORECASE) else 0.0
def network_risk(cmd):   return 1.0 if re.search(r'(http[s]?://|ftp://|\\\\)', cmd, re.IGNORECASE) else 0.0
def behavioural_risk(cmd):
    return 1.0 if re.search(r'\b(at|schtasks|regsvr32|rundll32|sc\.exe)\b', cmd, re.IGNORECASE) else 0.0
def history_risk(cmd):   return 0.0

# 3) score & label
weights = {
    'Lolbin (0.05)': 0.05,
    'Content (0.4)' : 0.4,
    'Frequency (0.2)': 0.2,
    'Source (0.1)'  : 0.1,
    'Network (0.1)' : 0.1,
    'Behavioural (0.1)': 0.1,
    'History (0.05)': 0.05
}

# apply
df['Lolbin (0.05)']     = df['prompt'].apply(lambda c: float(detect_lolbin(c)))
df['Content (0.4)']     = df['prompt'].apply(content_risk)
df['Frequency (0.2)']   = df['prompt'].apply(frequency_risk)
df['Source (0.1)']      = df['prompt'].apply(source_risk)
df['Network (0.1)']     = df['prompt'].apply(network_risk)
df['Behavioural (0.1)']  = df['prompt'].apply(behavioural_risk)
df['History (0.05)']    = df['prompt'].apply(history_risk)

df['Score'] = (
    df['Lolbin (0.05)']*weights['Lolbin (0.05)'] +
    df['Content (0.4)']*weights['Content (0.4)'] +
    df['Frequency (0.2)']*weights['Frequency (0.2)'] +
    df['Source (0.1)']*weights['Source (0.1)'] +
    df['Network (0.1)']*weights['Network (0.1)'] +
    df['Behavioural (0.1)']*weights['Behavioural (0.1)'] +
    df['History (0.05)']*weights['History (0.05)']
)

def assign_label(score):
    if   score >= 0.7: return 'malicious'
    elif score >= 0.3: return 'suspicious'
    else:              return 'benign'

df['Label'] = df['Score'].apply(assign_label)

def gen_response(cmd):
    parts = []
    if detect_lolbin(cmd):           parts.append("leverage built-in LOLbins")
    if content_risk(cmd) == 1.0:     parts.append("download or execute from a remote source")
    elif content_risk(cmd) == 0.5:   parts.append("perform file operations")
    if frequency_risk(cmd):          parts.append("schedule or automate execution")
    if network_risk(cmd):            parts.append("initiate network communication")
    if behavioural_risk(cmd):        parts.append("spawn processes or escalate privileges")
    desc = "; ".join(parts) or "perform standard operations"
    return f"This command could {desc}, potentially leading to unauthorized actions."

df['response'] = df['prompt'].apply(gen_response)

# 4) save
df.to_excel('dataset/windows_cmd_analyzed.xlsx', index=False)
print("✅ Analysis complete: windows_cmd_analyzed.xlsx")
