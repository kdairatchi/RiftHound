from __future__ import annotations
import re, shutil, subprocess
from dataclasses import dataclass, asdict

@dataclass
class ToolInfo:
    name: str
    path: str|None
    ready: bool
    version: str|None=None
    note: str=''
    deprecated: bool=False

ALIASES={'gxss':['Gxss','gxss'],'httpx':['httpx']}
CORE=['subfinder','amass','httpx','katana','gau','waymore','uro','gf','kxss','gxss','dalfox','arjun','fallparams','nuclei','rg','curl','jq']
OPTIONAL=['dnsx','naabu','ffuf','anew','unfurl','interactsh-client']

def which_tool(name:str):
    for x in ALIASES.get(name,[name]):
        p=shutil.which(x)
        if p: return p
    return None

def run_capture(cmd:list[str],stdin:str|None=None,timeout=900,cwd=None):
    try:
        cp=subprocess.run(cmd,input=stdin,text=True,capture_output=True,timeout=timeout,cwd=cwd,check=False)
        return cp.returncode,cp.stdout,cp.stderr
    except FileNotFoundError as e: return 127,'',str(e)
    except subprocess.TimeoutExpired as e: return 124,e.stdout or '',e.stderr or 'timeout'

def help_blob(path:str):
    for arg in ('-h','--help','-version','--version'):
        rc,so,se=run_capture([path,arg],timeout=15)
        if (so+se).strip(): return (so+'\n'+se)
    return ''

def inspect_tool(name:str)->ToolInfo:
    p=which_tool(name)
    if not p: return ToolInfo(name,None,False,note='not found')
    blob=help_blob(p); low=blob.lower(); ready=True; note=''; dep=False
    m=re.search(r'(?i)\bv?([0-9]+\.[0-9]+(?:\.[0-9]+)?)\b',blob)
    if name=='httpx':
        ready='projectdiscovery' in low or ('-td' in blob and '-silent' in blob and '-l' in blob)
        if not ready: note='binary-name collision: not ProjectDiscovery httpx'
    if name=='gxss': dep=True; note='legacy/archived upstream; corroborator only'
    if name=='nuclei' and '-ai' not in blob: note='AI prompt flag not detected'
    return ToolInfo(name,p,ready,m.group(1) if m else None,note,dep)

def doctor():
    tools={n:asdict(inspect_tool(n)) for n in CORE+OPTIONAL}
    return {'tools':tools,'ready_core':sum(1 for n in CORE if tools[n]['ready'])}
