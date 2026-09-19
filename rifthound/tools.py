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
OPTIONAL=['dnsx','naabu','nmap','searchsploit','msfconsole','jsattack','ffuf','anew','unfurl','interactsh-client','bbot']

# Only include tools with a maintained, deterministic upstream install route.
# OS-packaged tools are intentionally excluded: changing apt/brew packages from
# a scan orchestrator is surprising and can affect unrelated software.
TOOL_RECIPES={
 'subfinder':['go','install','github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'],
 'httpx':['go','install','github.com/projectdiscovery/httpx/cmd/httpx@latest'],
 'katana':['go','install','github.com/projectdiscovery/katana/cmd/katana@latest'],
 'gau':['go','install','github.com/lc/gau/v2/cmd/gau@latest'],
 'gf':['go','install','github.com/tomnomnom/gf@latest'],
 'dalfox':['go','install','github.com/hahwul/dalfox/v2@latest'],
 'fallparams':['go','install','github.com/ImAyrix/fallparams@latest'],
 'nuclei':['go','install','github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest'],
 'dnsx':['go','install','github.com/projectdiscovery/dnsx/cmd/dnsx@latest'],
 'naabu':['go','install','github.com/projectdiscovery/naabu/v2/cmd/naabu@latest'],
 'ffuf':['go','install','github.com/ffuf/ffuf/v2@latest'],
 'anew':['go','install','github.com/tomnomnom/anew@latest'],
 'unfurl':['go','install','github.com/tomnomnom/unfurl@latest'],
 'interactsh-client':['go','install','github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest'],
 'arjun':['pipx','install','arjun'],
 'uro':['pipx','install','uro'],
 'bbot':['pipx','install','bbot'],
}

def managed_tool_names():
    return sorted(TOOL_RECIPES)

def manage_tools(action:str,names:list[str]|None=None,all_tools:bool=False,apply:bool=False):
    """Plan or apply managed Go/pipx tool installs without invoking a shell."""
    if action not in {'install','update'}: raise ValueError('action must be install or update')
    selected=managed_tool_names() if all_tools else list(dict.fromkeys(names or []))
    unknown=sorted(set(selected)-set(TOOL_RECIPES))
    if unknown: raise ValueError('unsupported managed tool: '+', '.join(unknown))
    if not selected: raise ValueError('choose one or more tools, or use --all')
    rows=[]
    for name in selected:
        info=inspect_tool(name)
        if action=='install' and info.ready:
            rows.append({'name':name,'status':'skipped','reason':'already ready; use update to refresh it','command':TOOL_RECIPES[name]})
            continue
        if action=='update' and not info.ready:
            rows.append({'name':name,'status':'skipped','reason':'not ready; use install first','command':TOOL_RECIPES[name]})
            continue
        command=list(TOOL_RECIPES[name])
        # pipx separates first installation from upgrade, unlike Go where the
        # same ``go install ...@latest`` command covers both cases.
        if action=='update' and command[:2]==['pipx','install']:
            command=['pipx','upgrade',command[2]]
        if not apply:
            rows.append({'name':name,'status':'planned','reason':'add --yes to execute','command':command})
            continue
        rc,stdout,stderr=run_capture(command,timeout=1200)
        refreshed=inspect_tool(name)
        rows.append({'name':name,'status':'updated' if rc==0 and refreshed.ready else 'failed','returncode':rc,'ready':refreshed.ready,'command':command,'output':(stdout or stderr)[-1000:]})
    return {'action':action,'applied':apply,'results':rows}

def which_tool(name:str):
    for x in ALIASES.get(name,[name]):
        p=shutil.which(x)
        if p: return p
    return None

def run_capture(cmd:list[str],stdin:str|None=None,timeout:float=900,cwd:str|None=None):
    """Run a tool without raising, returning a shell-like result tuple."""
    try:
        cp=subprocess.run(cmd,input=stdin,text=True,capture_output=True,timeout=timeout,cwd=cwd,check=False)
        return cp.returncode,cp.stdout,cp.stderr
    except FileNotFoundError as e: return 127,'',str(e)
    except subprocess.TimeoutExpired as e:
        # ``TimeoutExpired`` can carry bytes even when text=True on older
        # Python releases, so normalize output for callers and JSON reports.
        stdout=e.stdout.decode(errors='replace') if isinstance(e.stdout,bytes) else (e.stdout or '')
        stderr=e.stderr.decode(errors='replace') if isinstance(e.stderr,bytes) else (e.stderr or 'timeout')
        return 124,stdout,stderr

def help_blob(path:str):
    for arg in ('-h','--help','-version','--version'):
        rc,so,se=run_capture([path,arg],timeout=15)
        if rc not in {126,127} and (so+se).strip(): return (so+'\n'+se)
    return ''

def inspect_tool(name:str)->ToolInfo:
    p=which_tool(name)
    if not p: return ToolInfo(name,None,False,note='not found')
    blob=help_blob(p); low=blob.lower(); ready=True; note=''; dep=False
    # Several pipeline-oriented tools (notably kxss) intentionally emit no
    # usage text and expect stdin.  A resolvable executable remains usable;
    # retain a diagnostic note instead of turning that into a false negative.
    if not blob: note='help/version output unavailable; presence only verified'
    m=re.search(r'(?i)\bv?([0-9]+\.[0-9]+(?:\.[0-9]+)?)\b',blob)
    if name=='httpx':
        ready='projectdiscovery' in low or ('-td' in blob and '-silent' in blob and '-l' in blob)
        if not ready: note='binary-name collision: not ProjectDiscovery httpx'
    if name=='bbot' and not blob:
        ready=False; note='BBOT did not start; repair or reinstall its Python environment'
    if name=='uro' and not blob:
        ready=False; note='URO did not start; repair or reinstall its Python environment'
    if name=='gxss': dep=True; note='legacy/archived upstream; corroborator only'
    if name=='nuclei' and '-ai' not in blob: note='AI prompt flag not detected'
    return ToolInfo(name,p,ready,m.group(1) if m else None,note,dep)

def doctor():
    tools={n:asdict(inspect_tool(n)) for n in CORE+OPTIONAL}
    missing_core=[n for n in CORE if not tools[n]['ready']]
    return {
        'tools':tools,
        'ready_core':len(CORE)-len(missing_core),
        'core_total':len(CORE),
        'missing_core':missing_core,
        'healthy':not missing_core,
    }
