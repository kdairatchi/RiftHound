from __future__ import annotations
import json,re
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlparse
WEIGHTS={'native':20,'dalfox':18,'nuclei':15,'kxss':8,'gxss':4,'gf':2,'arjun':5}
PROOF={'surface':5,'candidate':15,'strong-candidate':30,'validated-primitive':55}

def read_jsonl(path):
 p=Path(path);out=[]
 if not p.exists():return out
 for line in p.read_text(errors='replace').splitlines():
  try:out.append(json.loads(line))
  except:pass
 return out

def _key(f):
 u=f.get('url','');host=(urlparse(u).hostname or '').lower();return (f.get('family','OTHER'),host,f.get('parameter',''),urlparse(u).path)
def parse_kxss(text):
 out=[]
 for line in text.splitlines():
  m=re.search(r'(?:param\s+)?([A-Za-z0-9_.:\[\]-]+).*?on\s+(https?://\S+)',line,re.I)
  if m:out.append({'family':'XSS','url':m.group(2).rstrip('.,'),'parameter':m.group(1),'confidence':'candidate','tools':['kxss'],'score':20,'evidence_gate':['Native isolated reflection required'],'negative_controls':['clean baseline']})
 return out
def parse_gxss(text):
 out=[]
 for line in text.splitlines():
  m=re.search(r'https?://\S+',line)
  if m:out.append({'family':'XSS','url':m.group(0).rstrip('.,'),'parameter':'','confidence':'candidate','tools':['gxss'],'score':12,'evidence_gate':['Legacy corroborator only'],'negative_controls':['native isolated canary']})
 return out
def parse_dalfox(path):
 out=[]
 for o in read_jsonl(path):
  url=o.get('url') or o.get('target') or o.get('data') or o.get('poc') or ''
  if url:out.append({'family':'XSS','url':url,'parameter':o.get('param',''),'confidence':'strong-candidate','tools':['dalfox'],'score':45,'evidence_gate':['Reproduce outside Dalfox with controlled canary'],'negative_controls':['fresh session/control payload']})
 return out
def parse_nuclei(path):
 out=[]
 for o in read_jsonl(path):
  url=o.get('matched-at') or o.get('host') or o.get('url') or '';info=o.get('info') or {};name=info.get('name') or o.get('template-id','nuclei');low=(name+' '+o.get('template-id','')).lower();fam='XSS' if 'xss' in low else 'CORS' if 'cors' in low else 'SSRF' if 'ssrf' in low else 'OTHER'
  if url:out.append({'family':fam,'url':url,'parameter':'','confidence':'strong-candidate','tools':['nuclei'],'score':42,'evidence_gate':['Reproduce matcher manually or with independent deterministic request'],'negative_controls':['confirm not generic block/echo page']})
 return out
def aggregate(rows,quorum=2):
 groups=defaultdict(list)
 for r in rows:groups[_key(r)].append(r)
 out=[]
 for k,items in groups.items():
  base=dict(items[0]);tools=sorted({t for x in items for t in x.get('tools',['native'])});proof=max(items,key=lambda x:PROOF.get(x.get('confidence','candidate'),10)).get('confidence','candidate');score=PROOF.get(proof,10)+sum(WEIGHTS.get(t,2) for t in tools)
  fp=sorted({f for x in items for f in x.get('false_positive_flags',[])})
  penalties={'unstable-baseline':18,'bot-or-waf-challenge':20,'rate-limited-response':15,'non-html-reflection-context':5,'cross-host-redirect':10}
  score-=min(50,sum(penalties.get(x,4) for x in fp));
  if len(tools)>=quorum:score+=12
  score=max(0,min(100,score));status='validated/corroborated' if proof=='validated-primitive' and len(tools)>=quorum else 'corroborated' if len(tools)>=quorum else 'validated-native' if proof=='validated-primitive' else 'strong-lead' if score>=50 else 'lead'
  base.update({'tools':tools,'confidence':proof,'confidence_score':score,'status':status,'false_positive_flags':fp,'evidence_gate':list(dict.fromkeys(z for x in items for z in x.get('evidence_gate',[]))),'negative_controls':list(dict.fromkeys(z for x in items for z in x.get('negative_controls',[]))),'supporting_records':len(items)})
  out.append(base)
 return sorted(out,key=lambda x:(x['confidence_score'],len(x['tools'])),reverse=True)
