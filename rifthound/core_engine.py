from __future__ import annotations
import argparse, concurrent.futures, hashlib, json, os, random, re, string, time
from pathlib import Path
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse, quote
import requests, urllib3
from .models import Finding
from .fingerprints import scan_urls, scan_text
from .steps import STEP_CATALOG
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DOM_PATTERNS={
'postmessage':[r'addEventListener\s*\(\s*[\'\"]message',r'\.onmessage\s*=',r'postMessage\s*\('],
'dom-sink':[r'\.innerHTML\s*=',r'\.outerHTML\s*=',r'insertAdjacentHTML',r'document\.write\s*\(',r'createContextualFragment'],
'js-sink':[r'\beval\s*\(',r'new\s+Function\s*\(',r'setTimeout\s*\(\s*[\'\"]'],
'navigation-sink':[r'location\.(?:href|assign|replace)',r'window\.open\s*\('],
'messagechannel':[r'new\s+MessageChannel\s*\(',r'\.postMessage\([^)]*,\s*\[[^]]*port'],
'broadcastchannel':[r'new\s+BroadcastChannel\s*\('],
'window-name':[r'window\.name'],
'service-worker':[r'navigator\.serviceWorker\.register'],
'trusted-types':[r'trustedTypes\.createPolicy',r'require-trusted-types-for'],
'extension-bridge':[r'chrome\.runtime\.(?:sendMessage|connect)',r'browser\.runtime\.(?:sendMessage|connect)'],
'oauth-web-message':[r'response_mode.{0,80}web_message',r'web_message_uri'],
}
SQL_ERRORS=re.compile(r'(sql syntax|mysql_fetch|postgresql|pg_query|sqlite error|ora-\d{5}|microsoft ole db|unclosed quotation mark)',re.I)
STATE_RE=re.compile(r'(login|signin|account|profile|settings|security|password|reset|mfa|2fa|admin|billing|checkout|invite|oauth|saml|authorize)',re.I)
URL_PARAMS=re.compile(r'(url|uri|redirect|return|next|callback|webhook|image|avatar|fetch|proxy|dest|destination|continue)',re.I)

class Engine:
    def __init__(self,urls,headers=None,proxy='',timeout=15,threads=5,rps=6,verify=False,redact=True):
        self.urls=list(dict.fromkeys(urls));self.headers=headers or {};self.timeout=timeout;self.threads=max(1,threads);self.rps=float(rps or 0);self.verify=verify;self.redact=redact
        self.proxies={'http':proxy,'https':proxy} if proxy else None;self.session=requests.Session();self.findings=[];self.inventory=scan_urls(self.urls);self._last=0.0
    def _rate(self):
        if self.rps<=0:return
        gap=1.0/self.rps;now=time.monotonic();wait=gap-(now-self._last)
        if wait>0:time.sleep(wait)
        self._last=time.monotonic()
    def request(self,url,method='GET',headers=None,data=None,allow_redirects=True):
        self._rate();h={'User-Agent':'Mozilla/5.0 RiftHound/3.0'};h.update(self.headers);h.update(headers or {})
        try:
            r=self.session.request(method,url,headers=h,data=data,timeout=self.timeout,verify=self.verify,proxies=self.proxies,allow_redirects=allow_redirects)
            return r
        except requests.RequestException:return None
    def canary(self,prefix='RH'):return prefix+''.join(random.choice(string.ascii_letters+string.digits) for _ in range(12))
    def add(self,f:Finding):
        f.score=max(0,min(100,int(f.score)))
        if f.false_positive_flags and f.confidence!='validated-primitive':
            f.score=max(0,f.score-min(50,10*len(set(f.false_positive_flags))))
        if f.score>=80 and not f.false_positive_flags:f.report_state='report-candidate'
        elif f.score>=55:f.report_state='needs-validation'
        else:f.report_state='lead-only'
        self.findings.append(f.to_dict())
    def baseline(self,url):
        rs=[self.request(url) for _ in range(2)];rs=[r for r in rs if r]
        if len(rs)<2:return {'stable':False,'statuses':[]}
        a,b=rs;ha=hashlib.sha256(a.text.encode(errors='ignore')).hexdigest();hb=hashlib.sha256(b.text.encode(errors='ignore')).hexdigest()
        if ha==hb:return {'stable':True,'similarity':1.0,'status':a.status_code,'length':len(a.text)}
        la,lb=len(a.text),len(b.text);ratio=min(la,lb)/max(1,max(la,lb))
        return {'stable':ratio>.88 and a.status_code==b.status_code,'similarity':round(ratio,3),'status':a.status_code,'length':la}
    def mutate_param(self,url,param,value):
        p=urlparse(url);pairs=parse_qsl(p.query,keep_blank_values=True);found=False;out=[]
        for k,v in pairs:
            if k==param and not found:out.append((k,value));found=True
            else:out.append((k,v))
        if not found:out.append((param,value))
        return urlunparse(p._replace(query=urlencode(out,doseq=True)))
    def scan_reflections(self,url):
        p=urlparse(url);pairs=parse_qsl(p.query,keep_blank_values=True)
        for param,_ in list(dict.fromkeys(pairs)):
            c=self.canary();target=self.mutate_param(url,param,c);r=self.request(target)
            if not r:continue
            body=r.text;headers='\n'.join(f'{k}: {v}' for k,v in r.headers.items());places=[]
            if c in body:places.append('BODY')
            if c in headers:places.append('RESPONSE-HEADER')
            if not places:continue
            control=self.canary('CTRL');rc=self.request(self.mutate_param(url,param,control));isolated=bool(rc and control in rc.text)
            ct=r.headers.get('Content-Type','').lower();flags=[]
            if r.status_code==429:flags.append('rate-limited-response')
            if r.status_code in {401,403} and re.search(r'(captcha|challenge|access denied|verify you are human)',body,re.I):flags.append('bot-or-waf-challenge')
            if 'json' in ct or ct.startswith('text/plain'):flags.append('non-html-reflection-context')
            context='unknown';idx=body.find(c)
            if idx>=0:
                around=body[max(0,idx-120):idx+len(c)+120]
                if re.search(r'<script[^>]*>[^<]*'+re.escape(c),around,re.I|re.S):context='script'
                elif re.search(r'<[^>]+=[\'\"][^\'\"]*'+re.escape(c),around,re.I|re.S):context='quoted-attribute'
                elif re.search(r'<[^>]+>[^<]*'+re.escape(c),around,re.I|re.S):context='html-text'
                else:context='text'
            score=62 if isolated else 42
            self.add(Finding('XSS','Attributable reflected input',target,'low','strong-candidate' if isolated else 'candidate',param,evidence={'places':places,'context':context,'content_type':ct,'status':r.status_code,'isolated':isolated},evidence_gate=['Canary absent from baseline','Single parameter reproduces with fresh canary','Classify executable vs inert context before claiming XSS'],negative_controls=['Repeat with nearby benign value','Repeat in fresh session','Confirm response is not WAF/challenge page'],false_positive_flags=flags,score=score))
    def scan_dom(self,url):
        r=self.request(url)
        if not r:return
        host=(urlparse(url).hostname or '').lower();scan_text(host,r.text,self.inventory)
        for name,pats in DOM_PATTERNS.items():
            hits=[p for p in pats if re.search(p,r.text,re.I|re.S)]
            if not hits:continue
            fam='POSTMESSAGE' if name in {'postmessage','messagechannel','broadcastchannel','window-name','oauth-web-message'} else 'CLIENT'
            self.add(Finding(fam,f'Client-side surface: {name}',url,'info','surface',evidence={'surface':name,'patterns':hits[:5]},evidence_gate=['Trace attacker-controlled source to security-relevant sink','Prove relationship/origin/source assumptions rather than keyword co-location'],negative_controls=['Source without sink','Sink without attacker influence','Wrong origin/source/schema'],score=28 if name!='postmessage' else 40))
        if 'postmessage' in self.inventory.get(host,{}).get('surfaces',[]):
            weak=re.findall(r'(?:origin|e\.origin).{0,120}(?:includes|indexOf|startsWith|endsWith)\s*\(',r.text,re.I|re.S)
            if weak:self.add(Finding('POSTMESSAGE','Weak postMessage origin predicate candidate',url,'medium','strong-candidate',evidence={'weak_checks':weak[:5]},evidence_gate=['Confirm predicate applies to receiver handling sensitive message','Demonstrate controlled wrong-origin message accepted with harmless canary'],negative_controls=['Exact trusted origin','attacker suffix/prefix trap','wrong event.source','unknown message type'],score=68))
    def scan_cors(self,url):
        for origin in ('https://attacker.invalid','null'):
            r=self.request(url,headers={'Origin':origin})
            if not r:continue
            acao=r.headers.get('Access-Control-Allow-Origin','');acc=r.headers.get('Access-Control-Allow-Credentials','').lower()=='true'
            if acao==origin or (origin=='null' and acao=='null'):
                score=78 if acc and origin!='null' else 50
                self.add(Finding('CORS','CORS origin accepted',url,'medium' if score>=70 else 'low','strong-candidate',evidence={'origin':origin,'acao':acao,'credentials':acc,'status':r.status_code,'content_type':r.headers.get('Content-Type','')},evidence_gate=['Browser can read security-relevant response in owned authenticated session' if acc else 'Determine whether response contains security-relevant public data'],negative_controls=['Random Origin','trusted Origin','credentialed vs anonymous response'],score=score))
    def scan_redirect(self,url):
        params=[k for k,_ in parse_qsl(urlparse(url).query,keep_blank_values=True) if re.search(r'(redirect|return|next|url|continue|callback|dest)',k,re.I)]
        for param in params:
            marker='https://redirect-test.invalid/rh';t=self.mutate_param(url,param,marker);r=self.request(t,allow_redirects=False)
            if r and r.is_redirect and marker in r.headers.get('Location',''):
                self.add(Finding('REDIRECT','Open redirect candidate',t,'medium','validated-primitive',param,evidence={'status':r.status_code,'location':r.headers.get('Location')},evidence_gate=['Confirm target-controlled external origin is accepted server-side','For OAuth chains, separately prove callback/redirect binding'],negative_controls=['relative path','same-origin URL','nearby invalid scheme'],score=82))
    def scan_sqli(self,url):
        params=[k for k,_ in parse_qsl(urlparse(url).query,keep_blank_values=True)]
        for param in params:
            base=self.request(url);quote_r=self.request(self.mutate_param(url,param,"'"));paired=self.request(self.mutate_param(url,param,"''"))
            if not (base and quote_r and paired):continue
            qerr=SQL_ERRORS.search(quote_r.text);berr=SQL_ERRORS.search(base.text)
            if qerr and not berr:
                flags=[]
                if paired.status_code==quote_r.status_code and SQL_ERRORS.search(paired.text):flags.append('paired-quote-control-also-errors')
                self.add(Finding('SQLI','SQL error differential candidate',url,'medium','strong-candidate',param,evidence={'error':qerr.group(0),'base_status':base.status_code,'quote_status':quote_r.status_code,'paired_status':paired.status_code},evidence_gate=['Database-specific error absent from stable baseline','Confirm paired quote/control behavior differs predictably'],negative_controls=['paired quote','alphanumeric control','repeat baseline'],false_positive_flags=flags,score=70))
    def scan_ssti(self,url):
        params=[k for k,_ in parse_qsl(urlparse(url).query,keep_blank_values=True)]
        for param in params:
            a,b=random.randint(11,29),random.randint(31,47);marker=self.canary('S');payload=f'{marker}{{{{{a}*{b}}}}}{marker}';r=self.request(self.mutate_param(url,param,payload))
            if r and f'{marker}{a*b}{marker}' in r.text:
                self.add(Finding('SSTI','Arithmetic SSTI evaluation',url,'high','validated-primitive',param,evidence={'expression':f'{a}*{b}','result':a*b},evidence_gate=['Randomized arithmetic expression evaluates server-side','Do not escalate to command/file access for proof'],negative_controls=['literal expression','different arithmetic pair'],score=92))
    def scan_crlf(self,url):
        params=[k for k,_ in parse_qsl(urlparse(url).query,keep_blank_values=True)]
        for param in params:
            name='X-RiftHound-'+self.canary('H')[-6:];payload='rh%0d%0a'+name+'%3A%20ok';t=self.mutate_param(url,param,payload);r=self.request(t,allow_redirects=False)
            if r and r.headers.get(name)=='ok':
                self.add(Finding('CRLF','Response header injection',t,'high','validated-primitive',param,evidence={'header':name},evidence_gate=['New response header exists, not body reflection'],negative_controls=['encoded benign newline marker','fresh header name'],score=92))
    def scan_oauth_metadata(self,url):
        p=urlparse(url);base=f'{p.scheme}://{p.netloc}'
        for path in ('/.well-known/openid-configuration','/.well-known/oauth-authorization-server'):
            r=self.request(base+path)
            if not r or r.status_code>=400:continue
            try:o=r.json()
            except:continue
            keys=['issuer','authorization_endpoint','token_endpoint','jwks_uri','code_challenge_methods_supported','response_modes_supported','pushed_authorization_request_endpoint','device_authorization_endpoint','revocation_endpoint','end_session_endpoint','dpop_signing_alg_values_supported']
            meta={k:o.get(k) for k in keys if o.get(k) is not None};host=(p.hostname or '').lower();inv=self.inventory.setdefault(host,{'surfaces':[],'examples':{}});s=set(inv.get('surfaces',[]));s.update(['oauth','oidc'])
            if 'S256' in (o.get('code_challenge_methods_supported') or []):s.add('oauth-pkce')
            if any('web_message' in str(x) for x in (o.get('response_modes_supported') or [])):s.add('oauth-web-message')
            inv['surfaces']=sorted(s);inv['oauth_metadata']=meta
            self.add(Finding('OAUTH','OAuth/OIDC metadata discovered',base+path,'info','surface',evidence=meta,evidence_gate=['Inventory only; do not claim auth bypass from metadata'],negative_controls=['Compare documented/expected client behavior'],score=20));break
    def scan_headers(self,url):
        r=self.request(url)
        if not r:return
        low={k.lower():v for k,v in r.headers.items()};html='html' in low.get('content-type','').lower() or '<html' in r.text[:1000].lower()
        if html and STATE_RE.search(url+' '+r.text[:8000]):
            missing=[x for x in ('content-security-policy','x-frame-options','strict-transport-security') if x not in low]
            if missing:self.add(Finding('HEADERS','Security header posture on sensitive page',url,'info','surface',evidence={'missing':missing},evidence_gate=['Header absence alone is not a vulnerability; identify concrete exploit boundary'],negative_controls=['Compare equivalent sensitive route','Check meta CSP and frame-ancestors'],score=18))
        cache={k:v for k,v in r.headers.items() if k.lower() in {'cache-control','age','vary','via','x-cache','cf-cache-status','etag'}}
        if cache:
            host=(urlparse(url).hostname or '').lower();inv=self.inventory.setdefault(host,{'surfaces':[],'examples':{}});s=set(inv.get('surfaces',[]));s.add('cache');inv['surfaces']=sorted(s);inv['cache_headers']=cache
    def scan_url(self,url,modules):
        if 'reflection' in modules:self.scan_reflections(url)
        if 'dom' in modules:self.scan_dom(url)
        if 'cors' in modules:self.scan_cors(url)
        if 'redirect' in modules:self.scan_redirect(url)
        if 'sqli' in modules:self.scan_sqli(url)
        if 'ssti' in modules:self.scan_ssti(url)
        if 'crlf' in modules:self.scan_crlf(url)
        if 'headers' in modules:self.scan_headers(url)
        if 'oauth' in modules:self.scan_oauth_metadata(url)
    def run(self,modules=None):
        modules=modules or {'reflection','dom','cors','redirect','headers','oauth'}
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:list(ex.map(lambda u:self.scan_url(u,modules),self.urls))
        return self.findings

def read_urls(path):return [x.strip() for x in Path(path).read_text().splitlines() if x.strip()]
def main(argv=None):
    p=argparse.ArgumentParser(prog='python -m rifthound.core_engine');p.add_argument('-l','--urls',required=True);p.add_argument('-H','--header',action='append',default=[]);p.add_argument('-x','--proxy',default='');p.add_argument('-t','--threads',type=int,default=5);p.add_argument('--rps',type=float,default=6);p.add_argument('--timeout',type=int,default=15);p.add_argument('--verify-tls',action='store_true');p.add_argument('-o','--output');p.add_argument('--fingerprint-output');p.add_argument('--modules',default='reflection,dom,cors,redirect,headers,oauth');p.add_argument('--silent',action='store_true')
    ns=p.parse_args(argv);headers={}
    for h in ns.header:
        if ':' in h:k,v=h.split(':',1);headers[k.strip()]=v.strip()
    e=Engine(read_urls(ns.urls),headers,ns.proxy,ns.timeout,ns.threads,ns.rps,ns.verify_tls);rows=e.run(set(x.strip() for x in ns.modules.split(',') if x.strip()))
    if ns.output:
        Path(ns.output).parent.mkdir(parents=True,exist_ok=True);Path(ns.output).write_text('\n'.join(json.dumps(x,ensure_ascii=False) for x in rows)+'\n')
    if ns.fingerprint_output:Path(ns.fingerprint_output).write_text(json.dumps(e.inventory,indent=2)+'\n')
    if not ns.silent:
        for x in rows:print(f"[{x['score']:03}] {x['family']:<12} {x['report_state']:<18} {x['url']}")
    return 0
if __name__=='__main__':raise SystemExit(main())
