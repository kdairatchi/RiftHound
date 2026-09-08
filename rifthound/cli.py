from __future__ import annotations
import argparse,json,sys
from pathlib import Path
from urllib.parse import urlparse
from . import __version__
from .config import build_config,dump_default,merge
from .presets import PRESETS
from .tools import doctor
from .terminal import UI
from .pipeline import Pipeline
from .scope import normalize_url
from .packs import PACKS
from .steps import STEP_CATALOG
from .variants import FAMILIES

def parser():
 p=argparse.ArgumentParser(prog='rifthound',description='RiftHound — evidence-gated bug-bounty hunting framework by kdairatchi');p.add_argument('--version',action='version',version=f'RiftHound {__version__}');s=p.add_subparsers(dest='cmd')
 h=s.add_parser('hunt');h.add_argument('targets',nargs='*');h.add_argument('-d','--domain',action='append',default=[]);h.add_argument('-l','--urls');h.add_argument('-p','--preset',choices=sorted(PRESETS),default='balanced');h.add_argument('-c','--config');h.add_argument('-o','--out');h.add_argument('--phase',action='append',type=int,choices=[1,2,3,4]);h.add_argument('--all',action='store_true');h.add_argument('--ai',action='store_true');h.add_argument('--ai-prompt',action='append',default=[]);h.add_argument('--oast');h.add_argument('--proxy');h.add_argument('-H','--header',action='append',default=[]);h.add_argument('-t','--threads',type=int);h.add_argument('--rps',type=float);h.add_argument('--quorum',type=int);h.add_argument('--exclude-host',action='append',default=[]);h.add_argument('--exclude-regex',action='append',default=[]);h.add_argument('--recon-depth',type=int);h.add_argument('--max-urls',type=int);h.add_argument('--dry-run',action='store_true');h.add_argument('--quiet',action='store_true')
 s.add_parser('presets');d=s.add_parser('doctor');d.add_argument('--json',action='store_true');i=s.add_parser('init');i.add_argument('path',nargs='?',default='rifthound.yml');i.add_argument('--preset',choices=sorted(PRESETS),default='balanced');pk=s.add_parser('packs');pk.add_argument('name',nargs='?',default='ALL');st=s.add_parser('steps');st.add_argument('--json',action='store_true');v=s.add_parser('variants');v.add_argument('family',choices=sorted(FAMILIES));v.add_argument('value',nargs='?',default='');v.add_argument('--json',action='store_true');return p

def main(argv=None):
 argv=list(sys.argv[1:] if argv is None else argv);commands={'hunt','presets','doctor','init','packs','steps','variants','--help','-h','--version'}
 if argv and argv[0] not in commands and not argv[0].startswith('-'):argv=['hunt']+argv
 if not argv:argv=['--help']
 ns=parser().parse_args(argv)
 if ns.cmd=='presets':
  for n,c in PRESETS.items():print(f'{n:12} {c["description"]}')
  return 0
 if ns.cmd=='doctor':
  r=doctor();print(json.dumps(r,indent=2) if ns.json else '\n'.join(f"{n:18} {'READY' if x['ready'] else 'missing/not-ready'} {x.get('note','')}" for n,x in r['tools'].items()));return 0
 if ns.cmd=='init':dump_default(ns.path,ns.preset);print('[+] wrote',ns.path);return 0
 if ns.cmd=='packs':
  if ns.name.upper()=='ALL':
   for n in sorted(PACKS):print(f'\n## {n}\n{PACKS[n]}')
  else:print(PACKS.get(ns.name.upper(),'Unknown pack'))
  return 0
 if ns.cmd=='steps':print(json.dumps(STEP_CATALOG,indent=2) if ns.json else '\n'.join(f"{x['id']} phase={x['phase']} {x['title']}" for x in STEP_CATALOG));return 0
 if ns.cmd=='variants':
  if ns.family in {'origin','redirect','hpp'} and not ns.value:print('value required',file=sys.stderr);return 2
  rows=FAMILIES[ns.family](ns.value);print(json.dumps(rows,indent=2) if ns.json else '\n'.join(f"{r['name']:20} {(r.get('header')+': ' if r.get('header') else '')+r.get('value','')}\n  ↳ {r.get('purpose','')}" for r in rows));return 0
 if ns.cmd=='hunt':
  seeds=[];roots=list(ns.domain)
  for t in ns.targets:
   if '://' in t:
    u=normalize_url(t);seeds+=([u] if u else []);roots.append(urlparse(t).hostname or '')
   else:roots.append(t)
  if ns.urls:
   seeds += [normalize_url(x) for x in Path(ns.urls).read_text().splitlines() if normalize_url(x)]
  ov={'scope':{'roots':[x for x in roots if x]}}
  if ns.out:ov=merge(ov,{'project':{'output_dir':ns.out}})
  if ns.proxy:ov=merge(ov,{'http':{'proxy':ns.proxy}})
  if ns.header:ov=merge(ov,{'http':{'headers':ns.header}})
  if ns.threads:ov=merge(ov,{'http':{'threads':ns.threads}})
  if ns.rps is not None:ov=merge(ov,{'http':{'rps':ns.rps}})
  if ns.quorum:ov=merge(ov,{'validation':{'cross_tool_quorum':ns.quorum}})
  if ns.exclude_host:ov=merge(ov,{'scope':{'exclude_hosts':ns.exclude_host}})
  if ns.exclude_regex:ov=merge(ov,{'scope':{'exclude_regex':ns.exclude_regex}})
  if ns.recon_depth:ov=merge(ov,{'recon':{'depth':ns.recon_depth}})
  if ns.max_urls:ov=merge(ov,{'recon':{'max_urls':ns.max_urls}})
  if ns.ai:ov=merge(ov,{'validation':{'allow_nuclei_ai':True},'nuclei':{'ai':{'enabled':True,'prompts':ns.ai_prompt or ['reflection','cors','oauth-metadata']}}})
  if ns.oast:ov=merge(ov,{'validation':{'allow_oast':True,'oast_domain':ns.oast}})
  cfg=build_config(ns.preset,ns.config,ov);ui=UI(ns.quiet);ui.banner(__version__);ph=[1,2,3,4] if ns.all else sorted(set(ns.phase)) if ns.phase else cfg['phases'];ui.info(f'preset={ns.preset} phases={ph} roots={cfg["scope"]["roots"]}');Pipeline(cfg,ui,ns.dry_run).run(ph,seeds,ns.ai);return 0
 return 0
if __name__=='__main__':raise SystemExit(main())
