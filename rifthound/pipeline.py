from __future__ import annotations
import json, os, re, sys
from pathlib import Path
from urllib.parse import urlparse
from .tools import which_tool, run_capture, inspect_tool
from .scope import normalize_url,url_in_scope,host_in_roots,normalize_host
from .fingerprints import scan_urls,consume_httpx_jsonl
from .core_engine import Engine
from .evidence import read_jsonl,parse_kxss,parse_gxss,parse_dalfox,parse_nuclei,aggregate
from .chains import generate
from .reporting import write_html,write_markdown
from .ai_prompts import PROMPTS
from .correlation import nmap_services,nmap_vulnerability_candidates,searchsploit_results,metasploit_query

class Pipeline:
 def __init__(self,cfg,ui,dry_run=False):
  self.cfg=cfg;self.ui=ui;self.dry=dry_run;self.out=Path(cfg['project']['output_dir']).resolve();self.out.mkdir(parents=True,exist_ok=True);self.art=self.out/'artifacts';self.art.mkdir(exist_ok=True);self.logs=self.out/'logs';self.logs.mkdir(exist_ok=True);self.urls=[];self.subdomains=[]
 @property
 def roots(self):return [normalize_host(x) for x in self.cfg['scope'].get('roots',[]) if normalize_host(x)]
 def allowed(self,u):
  s=self.cfg['scope'];return url_in_scope(u,self.roots,s.get('include_hosts'),s.get('exclude_hosts'),s.get('exclude_regex'))
 def run_cmd(self,name,cmd,stdin=None,timeout=1800):
  self.ui.info(name+': '+' '.join(cmd))
  if self.dry:return 0,'',''
  rc,so,se=run_capture(cmd,stdin=stdin,timeout=timeout);(self.logs/(name+'.stdout.log')).write_text(so);(self.logs/(name+'.stderr.log')).write_text(se)
  self.ui.debug(f'{name}: exit={rc}, stdout={len(so)}B, stderr={len(se)}B, logs={self.logs/(name+".stdout.log")}')
  if rc not in (0,1):self.ui.warn(f'{name} exited {rc}')
  return rc,so,se
 def write_lines(self,p,lines):
  seen=[];s=set()
  for x in lines:
   x=x.strip()
   if x and x not in s:s.add(x);seen.append(x)
  Path(p).write_text('\n'.join(seen)+('\n' if seen else ''));return seen
 def bbot_results(self, directory):
  """Extract only in-scope hosts and URLs from BBOT's JSON event output."""
  hosts=set();urls=set()
  for path in Path(directory).rglob('*.json'):
   try: payload=json.loads(path.read_text(errors='replace'))
   except (OSError,json.JSONDecodeError):
    try: payload=[json.loads(line) for line in path.read_text(errors='replace').splitlines() if line.strip()]
    except (OSError,json.JSONDecodeError): continue
   for event in payload if isinstance(payload,list) else [payload]:
    data=event.get('data',event) if isinstance(event,dict) else event
    values=[data] if isinstance(data,str) else [data.get(k,'') for k in ('url','host') if isinstance(data,dict)]
    for value in values:
     url=normalize_url(value) if isinstance(value,str) and '://' in value else None
     host=normalize_host(urlparse(url).hostname) if url else normalize_host(value if isinstance(value,str) else '')
     if host and host_in_roots(host,self.roots):
      hosts.add(host)
      if url and self.allowed(url): urls.add(url)
  return hosts,urls
 def phase1(self,seeds):
  self.ui.phase(1,'Recon & Surface Inventory','subfinder/amass/httpx/katana/gau + scope normalization')
  domains=set(self.roots)
  for u in seeds:
   n=normalize_url(u)
   if n and self.allowed(n):self.urls.append(n);domains.add(urlparse(n).hostname or '')
  for root in self.roots:
   if which_tool('subfinder'):
    _,so,_=self.run_cmd('subfinder-'+root,[which_tool('subfinder'),'-d',root,'-silent']);domains.update(so.splitlines())
   if which_tool('amass'):
    _,so,_=self.run_cmd('amass-'+root,[which_tool('amass'),'enum','-passive','-d',root]);domains.update(so.splitlines())
  bbot_cfg=self.cfg['recon'].get('bbot',{})
  bbot_urls=set()
  bbot=inspect_tool('bbot')
  if bbot_cfg.get('enabled') and bbot.ready:
   for root in self.roots:
    output=self.art/'bbot'/root
    cmd=[bbot.path,'-t',root,'-f',bbot_cfg.get('preset','subdomain-enum'),'-om','json','-o',str(output),'-y']
    for flag in bbot_cfg.get('require_flags',['passive']): cmd.extend(['-rf',flag])
    self.run_cmd('bbot-'+root,cmd,timeout=3600)
    found_hosts,found_urls=self.bbot_results(output);domains.update(found_hosts);bbot_urls.update(found_urls)
  elif bbot_cfg.get('enabled'):
   self.ui.warn('BBOT requested but not ready; run rifthound doctor for repair guidance')
  self.subdomains=sorted({normalize_host(d) for d in domains if normalize_host(d) and (not self.roots or host_in_roots(d,self.roots))});self.write_lines(self.art/'subdomains.txt',self.subdomains)
  recon=self.cfg.get('recon',{})
  if recon.get('dnsx',{}).get('enabled') and which_tool('dnsx') and self.subdomains:
   self.run_cmd('dnsx',[which_tool('dnsx'),'-l',str(self.art/'subdomains.txt'),'-a','-json','-silent','-duc','-o',str(self.art/'dnsx.jsonl')],timeout=1800)
  live=[];hi=inspect_tool('httpx')
  if hi.ready and self.subdomains:
   out=self.art/'httpx.jsonl';cmd=[hi.path,'-l',str(self.art/'subdomains.txt'),'-silent','-j','-sc','-ct','-title','-server','-td','-cdn','-location','-o',str(out)];self.run_cmd('httpx',cmd)
   if out.exists():
    for l in out.read_text(errors='replace').splitlines():
     try:u=json.loads(l).get('url')
     except:continue
     if u and self.allowed(u):live.append(u)
  if not live:live=['https://'+d for d in self.subdomains]
  live.extend(bbot_urls)
  self.write_lines(self.art/'live.txt',live);self.urls.extend(live)
  if which_tool('katana') and live:
   _,so,_=self.run_cmd('katana',[which_tool('katana'),'-list',str(self.art/'live.txt'),'-silent','-d',str(self.cfg['recon'].get('depth',3)),'-jc','-kf','robotstxt,sitemapxml']);self.urls.extend(so.splitlines())
  if which_tool('gau'):
   for root in self.roots:
    _,so,_=self.run_cmd('gau-'+root,[which_tool('gau'),'--subs',root]);self.urls.extend(so.splitlines())
  if recon.get('waymore',{}).get('enabled') and which_tool('waymore'):
   for root in self.roots:
    output=self.art/(f'waymore-{root}.txt');self.run_cmd('waymore-'+root,[which_tool('waymore'),'-i',root,'-mode','U','-oU',str(output),'-nlf'],timeout=3600)
    if output.exists():self.urls.extend(output.read_text(errors='replace').splitlines())
  scoped=[];seen=set();limit=int(self.cfg['recon'].get('max_urls',50000))
  for x in self.urls:
   n=normalize_url(x)
   if n and self.allowed(n) and n not in seen:seen.add(n);scoped.append(n)
   if len(scoped)>=limit:break
  self.urls=scoped;self.write_lines(self.art/'urls.txt',self.urls)
  inv=scan_urls(self.urls);inv=consume_httpx_jsonl(self.art/'httpx.jsonl',inv);(self.art/'fingerprints-passive.json').write_text(json.dumps(inv,indent=2)+'\n');self.ui.ok(f'phase 1: {len(self.subdomains)} hosts, {len(self.urls)} URLs')
 def phase2(self):
  self.ui.phase(2,'Discovery','gf/Arjun/kxss/Gxss + native DOM/postMessage/client analysis')
  parameterized=[u for u in self.urls if '?' in u and '=' in u];self.write_lines(self.art/'parameterized.txt',parameterized)
  if which_tool('gf') and self.urls:
   d=self.art/'gf';d.mkdir(exist_ok=True)
   for fam in ['xss','sqli','ssrf','lfi','redirect','idor','ssti']:
    rc,so,_=self.run_cmd('gf-'+fam,[which_tool('gf'),fam],stdin='\n'.join(self.urls)+'\n');
    if rc in (0,1):self.write_lines(d/(fam+'.txt'),so.splitlines())
  if which_tool('kxss') and parameterized:
   _,so,_=self.run_cmd('kxss',[which_tool('kxss')],stdin='\n'.join(parameterized)+'\n');(self.art/'kxss.txt').write_text(so)
  if which_tool('gxss') and parameterized:
   self.ui.warn('Gxss is legacy/archived; corroborator only');_,so,_=self.run_cmd('gxss',[which_tool('gxss'),'-p','RIFTHOUND','-c','20'],stdin='\n'.join(parameterized)+'\n');(self.art/'gxss.txt').write_text(so)
  if which_tool('fallparams') and self.urls:
   # FallParams enriches the local parameter corpus.  It receives the already
   # scope-filtered URL list and does not enable its own crawl/headless modes.
   output=self.art/'fallparams.txt'
   self.run_cmd('fallparams',[which_tool('fallparams'),'-u',str(self.art/'urls.txt'),'-o',str(output),'-silent','-duc'])
  if self.cfg.get('recon',{}).get('arjun',{}).get('enabled') and which_tool('arjun') and self.urls:
   self.run_cmd('arjun',[which_tool('arjun'),'-i',str(self.art/'urls.txt'),'-o',str(self.art/'arjun.json'),'-q','-t',str(self.cfg['http'].get('threads',5)),'-T',str(self.cfg['http'].get('timeout',15)),'--rate-limit',str(self.cfg['http'].get('rps',6))],timeout=3600)
  if which_tool('uro') and self.urls:
   _,normalized,_=self.run_cmd('uro',[which_tool('uro')],stdin='\n'.join(self.urls)+'\n',timeout=300)
   if normalized:self.urls=self.write_lines(self.art/'urls-uro.txt',normalized.splitlines());self.write_lines(self.art/'urls.txt',self.urls)
  if self.cfg.get('recon',{}).get('jsattack',{}).get('enabled') and which_tool('jsattack') and self.urls:
   output=self.art/'jsattack';cmd=[which_tool('jsattack'),'analyze','--list',str(self.art/'urls.txt'),'--depth','0','--out',str(output),'--threads',str(self.cfg['http'].get('threads',5)),'--rate',str(self.cfg['http'].get('rps',6)),'--timeout',str(self.cfg['http'].get('timeout',15)),'--silent']
   self.run_cmd('jsattack',cmd,timeout=3600)
  self.native('discovery',{'reflection','dom','headers','oauth'})
 def native(self,name,mods):
  h={}
  for item in self.cfg['http'].get('headers',[]):
   if ':' in item:k,v=item.split(':',1);h[k.strip()]=v.strip()
  e=Engine(self.urls,h,self.cfg['http'].get('proxy',''),self.cfg['http'].get('timeout',15),self.cfg['http'].get('threads',5),self.cfg['http'].get('rps',6),self.cfg['http'].get('verify_tls',False));rows=[] if self.dry else e.run(mods);p=self.art/f'core-{name}.jsonl';p.write_text('\n'.join(json.dumps(x) for x in rows)+('\n' if rows else ''));(self.art/f'fingerprints-{name}.json').write_text(json.dumps(e.inventory,indent=2)+'\n')
 def service_correlation(self):
  cfg=self.cfg['recon'].get('service_correlation',{}); out=self.art/'service-correlation';out.mkdir(exist_ok=True)
  if not (which_tool('naabu') and which_tool('nmap')): self.ui.warn('Service correlation needs both naabu and nmap');return
  ports=out/'naabu.jsonl';self.run_cmd('naabu',[which_tool('naabu'),'-l',str(self.art/'subdomains.txt'),'-top-ports',str(cfg.get('top_ports',100)),'-json','-silent','-o',str(ports)],timeout=3600)
  open_ports={}
  for row in read_jsonl(ports):
   host=normalize_host(row.get('host',''));port=row.get('port')
   if host and host_in_roots(host,self.roots) and isinstance(port,int):open_ports.setdefault(host,[]).append(port)
  services=[]
  for host,port_list in open_ports.items():
   report=out/(host.replace(':','_')+'.xml');self.run_cmd('nmap-'+host,[which_tool('nmap'),'-sV','--version-light','-Pn','--open','-p',','.join(map(str,sorted(set(port_list)))),'-oX',str(report),host],timeout=1800);services.extend(nmap_services(report))
  vuln_candidates=[]
  if cfg.get('nmap_vuln'):
   for host,port_list in open_ports.items():
    report=out/(host.replace(':','_')+'-vuln.xml');cmd=[which_tool('nmap'),'-sV','--version-light','--script','vuln and not (intrusive or exploit or dos or brute)','--script-timeout','30s','-Pn','--open','-p',','.join(map(str,sorted(set(port_list)))),'-oX',str(report),host];self.run_cmd('nmap-vuln-'+host,cmd,timeout=1800);vuln_candidates.extend(nmap_vulnerability_candidates(report))
  matches=[];msf=[]
  for service in services:
   query=metasploit_query(service)
   if not query: continue
   if which_tool('searchsploit'):
    _,stdout,_=self.run_cmd('searchsploit-'+query,[which_tool('searchsploit'),'-j','-t',query],timeout=60)
    for hit in searchsploit_results(stdout): matches.append({**service,'query':query,**hit})
   if cfg.get('metasploit_search',True) and which_tool('msfconsole'):
    _,stdout,_=self.run_cmd('metasploit-search-'+query,[which_tool('msfconsole'),'-q','-x',f'search type:exploit {query}; exit'],timeout=120);msf.append({'query':query,'output':stdout[:12000]})
  report={'disclaimer':'Version, catalog, and Nmap NSE matches are triage leads only. Confirm exact version, reachability, scope, and harmless impact before reporting. Exploit, intrusive, DoS, and brute-force NSE categories are excluded; no exploit was executed or copied.','services':services,'nmap_vulnerability_candidates':vuln_candidates,'searchsploit_matches':matches,'metasploit_searches':msf};(out/'version-correlation.json').write_text(json.dumps(report,indent=2)+'\n')
 def phase3(self,ai=False):
  self.ui.phase(3,'Validation & FP Control','native differentials + Dalfox/Nuclei corroboration')
  mods={'reflection','dom','headers','oauth','cors','redirect'}
  preset=self.cfg.get('preset','balanced')
  if preset in {'server','deep','full'}:mods|={'sqli','ssti','crlf'}
  self.native('validation',mods)
  if self.cfg['recon'].get('service_correlation',{}).get('enabled'):self.service_correlation()
  param=self.art/'parameterized.txt'
  if which_tool('dalfox') and param.exists() and param.stat().st_size:
   self.run_cmd('dalfox',[which_tool('dalfox'),'scan',str(param),'--format','jsonl','--output',str(self.art/'dalfox.jsonl')],timeout=3600)
  if which_tool('nuclei'):
   cmd=[which_tool('nuclei'),'-l',str(self.art/'urls.txt'),'-jsonl','-o',str(self.art/'nuclei.jsonl'),'-severity',self.cfg['nuclei']['severity'],'-etags',self.cfg['nuclei']['exclude_tags'],'-rl',str(self.cfg['http'].get('rps',6))]
   if self.cfg['nuclei'].get('automatic_scan'):cmd+=['-as']
   self.run_cmd('nuclei',cmd,timeout=7200)
   if ai and self.cfg['validation'].get('allow_nuclei_ai') and os.environ.get('PDCP_API_KEY'):
    for n in self.cfg['nuclei']['ai'].get('prompts',[])[:self.cfg['nuclei']['ai'].get('max_prompts',3)]:
     self.run_cmd('nuclei-ai-'+n,[which_tool('nuclei'),'-l',str(self.art/'urls.txt'),'-ai',PROMPTS.get(n,n),'-rl',str(self.cfg['http'].get('rps',6))],timeout=3600)
 def phase4(self):
  self.ui.phase(4,'Correlation, Chains & Evidence Gates','cross-tool quorum, FP penalties, ranked next actions')
  rows=[]
  for p in [self.art/'core-discovery.jsonl',self.art/'core-validation.jsonl']:rows+=read_jsonl(p)
  if (self.art/'kxss.txt').exists():rows+=parse_kxss((self.art/'kxss.txt').read_text())
  if (self.art/'gxss.txt').exists():rows+=parse_gxss((self.art/'gxss.txt').read_text())
  rows+=parse_dalfox(self.art/'dalfox.jsonl');rows+=parse_nuclei(self.art/'nuclei.jsonl')
  ranked=aggregate(rows,int(self.cfg['validation'].get('cross_tool_quorum',2)));(self.out/'evidence-ledger.json').write_text(json.dumps(ranked,indent=2)+'\n')
  fps={}
  for p in [self.art/'fingerprints-passive.json',self.art/'fingerprints-discovery.json',self.art/'fingerprints-validation.json']:
   if p.exists():
    try:d=json.loads(p.read_text())
    except:continue
    for h,v in d.items():
     dst=fps.setdefault(h,{'surfaces':[],'examples':{}});dst['surfaces']=sorted(set(dst.get('surfaces',[]))|set(v.get('surfaces',[])));dst['examples'].update(v.get('examples',{}))
  for r in ranked:
   h=(urlparse(r.get('url','')).hostname or '').lower();
   if h:fps.setdefault(h,{'surfaces':[],'examples':{}})['surfaces']=sorted(set(fps[h]['surfaces'])|{r.get('family','').lower()})
  chains=generate(fps,ranked);(self.out/'chain-hypotheses.json').write_text(json.dumps(chains,indent=2)+'\n');summary={'tool':'RiftHound','author':'kdairatchi','preset':self.cfg.get('preset'),'urls':len(self.urls),'signals':len(ranked),'corroborated':sum('corroborated' in r['status'] for r in ranked),'chains':len(chains)};(self.out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n');write_html(self.out/'rifthound-report.html',summary,ranked,chains);write_markdown(self.out/'rifthound-report.md',summary,ranked,chains);self.ui.findings(ranked);self.ui.ok(f'phase 4: {len(ranked)} signals, {len(chains)} chain hypotheses');return ranked
 def run(self,phases,seeds,ai=False):
  if 1 in phases:self.phase1(seeds)
  else:self.urls=[u for u in seeds if self.allowed(u)];self.write_lines(self.art/'urls.txt',self.urls)
  if 2 in phases:self.phase2()
  if 3 in phases:self.phase3(ai)
  if 4 in phases:return self.phase4()
  return []
