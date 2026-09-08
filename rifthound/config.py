from __future__ import annotations
from copy import deepcopy
from pathlib import Path
import yaml
from .presets import get_preset
DEFAULT={
'project':{'name':'hunt','output_dir':'rifthound-work','author':'kdairatchi'},
'scope':{'roots':[],'include_hosts':[],'exclude_hosts':[],'exclude_regex':[],'require_https':False},
'http':{'headers':[],'proxy':'','timeout':15,'verify_tls':False,'threads':5,'rps':6},
'recon':{'depth':3,'max_urls':50000},
'validation':{'cross_tool_quorum':2,'allow_oast':False,'oast_domain':'','allow_nuclei_ai':False},
'nuclei':{'automatic_scan':True,'severity':'info,low,medium,high,critical','exclude_tags':'dos,fuzz,intrusive','ai':{'enabled':False,'prompts':['reflection','cors','oauth-metadata'],'max_prompts':3}},
'evidence':{'html_report':True,'markdown_report':True,'redact':True},
}
def merge(a,b):
    out=deepcopy(a)
    for k,v in (b or {}).items():
        out[k]=merge(out[k],v) if isinstance(v,dict) and isinstance(out.get(k),dict) else deepcopy(v)
    return out

def build_config(preset='balanced',path=None,overrides=None):
    cfg=merge(DEFAULT,get_preset(preset)); cfg['preset']=preset
    if path: cfg=merge(cfg,yaml.safe_load(Path(path).read_text()) or {})
    return merge(cfg,overrides or {})

def dump_default(path,preset='balanced'):
    Path(path).write_text(yaml.safe_dump(build_config(preset),sort_keys=False))
