from __future__ import annotations
import re, json
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlparse

URL_FPS={
'wordpress':[r'/wp-(?:content|includes|json)/',r'[?&]rest_route='],
'drupal':[r'/sites/default/',r'/core/misc/'],'joomla':[r'/components/com_'],
'nextjs':[r'/_next/'],'nuxt':[r'/_nuxt/'],'sveltekit':[r'/_app/immutable/'],'gatsby':[r'/page-data/'],
'graphql':[r'/graphql(?:/|$|\?)',r'/gql(?:/|$|\?)'],'grpc-web':[r'/grpc(?:/|$)',r'grpc-web'],
'json-rpc':[r'/jsonrpc',r'/rpc(?:/|$|\?)'],'oauth':[r'/oauth2?/',r'/authorize(?:\?|$)',r'/callback(?:\?|$)'],
'oidc':[r'openid-configuration',r'/oidc/'],'saml':[r'/saml',r'RelayState='],'webauthn':[r'webauthn',r'passkey'],
'websocket':[r'^wss?://',r'/socket\.io/',r'/ws(?:/|$|\?)'],'sse':[r'/events(?:/|$|\?)',r'/sse(?:/|$|\?)'],
'openapi':[r'openapi\.json',r'swagger\.json',r'/api-docs'],'signed-url':[r'X-Amz-Signature=',r'X-Goog-Signature=',r'[?&](?:sig|signature)='],
'firebase':[r'firebaseio\.com'],'supabase':[r'supabase\.co',r'/rest/v1/',r'/auth/v1/'],'auth0':[r'auth0\.com'],
'okta':[r'okta\.com'],'cognito':[r'amazoncognito\.com',r'cognito-idp'],'keycloak':[r'/realms/[^/]+/protocol/openid-connect'],
'entra-id':[r'login\.microsoftonline\.com'],'hasura':[r'/v1/graphql',r'/v2/query'],'postgrest':[r'/rest/v1/'],'trpc':[r'/api/trpc/',r'/trpc/'],
'service-worker':[r'service-worker\.js',r'/sw\.js'],'source-map':[r'\.map(?:\?|$)'],'ai-api':[r'/v1/(?:chat/completions|responses|embeddings)',r'/mcp(?:/|$)',r'/agents?(?:/|$)'],
's3':[r's3[.-][a-z0-9-]+\.amazonaws\.com',r's3\.amazonaws\.com'],'azure-blob':[r'\.blob\.core\.windows\.net'],'gcs':[r'storage\.googleapis\.com'],
}
TEXT_FPS={
'react':[r'__REACT_DEVTOOLS_GLOBAL_HOOK__',r'react(?:\.production)?\.min\.js'],'angular':[r'ng-version=',r'angular\.module\('],'vue':[r'__VUE__',r'Vue\.component\('],
'postmessage':[r'postMessage\s*\(',r'addEventListener\s*\(\s*[\'\"]message'],'messagechannel':[r'new\s+MessageChannel\s*\('],
'broadcastchannel':[r'new\s+BroadcastChannel\s*\('],'window-name':[r'window\.name'],'service-worker':[r'navigator\.serviceWorker\.register'],
'trusted-types':[r'require-trusted-types-for',r'trustedTypes\.createPolicy'],'persisted-graphql':[r'persistedQuery',r'sha256Hash'],
'grpc-web':[r'application/grpc-web',r'grpc-web-text'],'webauthn':[r'navigator\.credentials\.(?:create|get)',r'PublicKeyCredential'],
'websocket':[r'new\s+WebSocket\s*\('],'sse':[r'new\s+EventSource\s*\(',r'text/event-stream'],'webtransport':[r'new\s+WebTransport\s*\('],
'extension-bridge':[r'chrome\.runtime\.(?:sendMessage|connect)',r'browser\.runtime\.(?:sendMessage|connect)'],
'prototype-pollution-surface':[r'__proto__',r'constructor\s*\[\s*[\'\"]prototype'],'wasm':[r'WebAssembly\.(?:instantiate|compile)'],
'nextjs-rsc':[r'__next_f',r'text/x-component',r'Next-Action'],'trpc':[r'@trpc/client',r'TRPCClientError'],'apollo-graphql':[r'ApolloClient',r'__APOLLO_STATE__'],
'hasura':[r'x-hasura-role',r'x-hasura-admin-secret'],'oauth-web-message':[r'response_mode.{0,80}web_message',r'web_message_uri'],
'oauth-pkce':[r'code_challenge',r'code_verifier',r'S256'],'oauth-dpop':[r'DPoP',r'dpop_jkt'],'saml-relaystate':[r'RelayState',r'SAMLResponse'],
'payment-request':[r'new\s+PaymentRequest\s*\('],'webusb':[r'navigator\.usb'],'webbluetooth':[r'navigator\.bluetooth'],
}
HEADER_FPS={
'cloudflare':[('server',r'cloudflare'),('cf-ray',r'.+')],'fastly':[('via',r'varnish'),('x-served-by',r'cache-')],
'cloudfront':[('x-amz-cf-id',r'.+'),('via',r'cloudfront')],'vercel':[('server',r'vercel'),('x-vercel-id',r'.+')],
'netlify':[('server',r'netlify'),('x-nf-request-id',r'.+')],'envoy':[('server',r'envoy')],'nginx':[('server',r'nginx')],
'apache':[('server',r'apache')],'iis':[('server',r'microsoft-iis')],'varnish':[('x-varnish',r'.+')],'aws-alb':[('x-amzn-trace-id',r'.+')],
}
SECURITY_HEADERS={'content-security-policy','strict-transport-security','cross-origin-opener-policy','cross-origin-embedder-policy','cross-origin-resource-policy','permissions-policy','referrer-policy','x-frame-options','x-content-type-options'}

def scan_urls(urls):
    d=defaultdict(lambda:{'surfaces':set(),'examples':defaultdict(list)})
    for url in urls:
        host=(urlparse(url).hostname or '').lower()
        if not host: continue
        for name,pats in URL_FPS.items():
            if any(re.search(p,url,re.I) for p in pats):
                d[host]['surfaces'].add(name)
                if len(d[host]['examples'][name])<5:d[host]['examples'][name].append(url)
    return {h:{'surfaces':sorted(v['surfaces']),'examples':dict(v['examples'])} for h,v in d.items()}

def scan_text(host,text,result):
    h=result.setdefault(host,{'surfaces':[],'examples':{}}); s=set(h.get('surfaces',[]))
    for name,pats in TEXT_FPS.items():
        if any(re.search(p,text,re.I|re.S) for p in pats): s.add(name)
    h['surfaces']=sorted(s)

def consume_httpx_jsonl(path,result=None):
    out=result or {}; p=Path(path)
    if not p.exists(): return out
    for line in p.read_text(errors='replace').splitlines():
        try:o=json.loads(line)
        except:continue
        url=o.get('url') or o.get('input') or ''; host=(urlparse(url).hostname or o.get('host') or '').lower()
        if not host:continue
        h=out.setdefault(host,{'surfaces':[],'examples':{}}); s=set(h.get('surfaces',[]))
        for t in o.get('tech',[]) or o.get('technologies',[]) or []:s.add(str(t).lower())
        hdr=o.get('header') or o.get('headers') or {}
        if isinstance(hdr,dict):
            low={str(k).lower():str(v) for k,v in hdr.items()}
            for name,rules in HEADER_FPS.items():
                if any(k in low and re.search(p,low[k],re.I) for k,p in rules):s.add(name)
            sec=sorted(k for k in low if k in SECURITY_HEADERS)
            if sec:h['security_headers']=sec
        h['surfaces']=sorted(s)
    return out
