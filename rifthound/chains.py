from __future__ import annotations
from collections import defaultdict
from urllib.parse import urlparse
RULES=[
('RH-CHAIN-000',{'postmessage','oauth'},'postMessage trust → OAuth response exposure → controlled ATO path',88),
('RH-CHAIN-001',{'postmessage','trusted-types'},'postMessage dataflow → DOM sink → Trusted Types gadget review',68),
('RH-CHAIN-002',{'postmessage','extension-bridge'},'page message → extension/native bridge → privileged capability',90),
('RH-CHAIN-003',{'messagechannel','oauth'},'MessagePort handoff → OAuth response channel confusion',82),
('RH-CHAIN-004',{'window-name','oauth'},'window.name persistence → callback/navigation state confusion',66),
('RH-CHAIN-010',{'service-worker','oauth'},'service worker fetch interception → OAuth callback/cache review',70),
('RH-CHAIN-011',{'service-worker','signed-url'},'service worker cache → signed URL persistence/scope review',62),
('RH-CHAIN-020',{'graphql','persisted-graphql'},'persisted GraphQL → authorization/cache consistency',72),
('RH-CHAIN-021',{'graphql','signed-url'},'GraphQL resolver → signed URL issuance/binding review',70),
('RH-CHAIN-022',{'graphql','websocket'},'GraphQL subscriptions → WebSocket auth/channel matrix',74),
('RH-CHAIN-030',{'grpc-web','oauth'},'gRPC-Web method surface → session method-level authorization',66),
('RH-CHAIN-040',{'saml','redirect'},'SAML RelayState/destination → open redirect/state binding',72),
('RH-CHAIN-042',{'deep-link','oauth'},'deep/custom link → OAuth callback ownership/routing',82),
('RH-CHAIN-050',{'webauthn','oauth'},'passkey enrollment/recovery → OAuth session invalidation matrix',64),
('RH-CHAIN-060',{'signed-url','s3'},'S3 signed URL → method/object/expiry binding',68),
('RH-CHAIN-061',{'signed-url','azure-blob'},'Azure signed URL/SAS → object/permission binding',68),
('RH-CHAIN-062',{'signed-url','gcs'},'GCS signed URL → method/object/expiry binding',68),
('RH-CHAIN-070',{'wordpress','source-map'},'WordPress/plugin JS + sourcemap → hidden REST/AJAX mapping',58),
('RH-CHAIN-072',{'wordpress','oauth'},'WordPress OAuth/SSO plugin → callback/account-link review',64),
('RH-CHAIN-080',{'nextjs','source-map'},'Next.js chunks/sourcemaps → API/action inventory',52),
('RH-CHAIN-081',{'nextjs','oauth'},'Next.js auth callback/client bundle → state/redirect/session review',58),
('RH-CHAIN-090',{'supabase','graphql'},'Supabase/GraphQL → row/object authorization matrix',76),
('RH-CHAIN-091',{'firebase','oauth'},'Firebase identity/session → OAuth/deep-link account binding',72),
('RH-CHAIN-100',{'websocket','oauth'},'WebSocket session → cookie/Origin matrix',72),
('RH-CHAIN-101',{'sse','oauth'},'SSE/EventSource → credentialed cross-origin/session review',58),
('RH-CHAIN-110',{'ai-api','signed-url'},'AI/agent API → attachment/signed URL trust boundary',58),
('RH-CHAIN-111',{'ai-api','websocket'},'AI streaming channel → conversation/session authorization',56),
('RH-CHAIN-120',{'prototype-pollution-surface','postmessage'},'message merge → prototype pollution → client sink',74),
('RH-CHAIN-130',{'payment-request','postmessage'},'payment bridge → origin/source/amount binding',72),
('RH-CHAIN-160',{'cors','graphql'},'CORS trust failure → GraphQL authenticated read boundary',78),
('RH-CHAIN-161',{'cors','oauth'},'CORS trust failure → OAuth/session endpoint exposure review',72),
('RH-CHAIN-162',{'redirect','oauth'},'open redirect → OAuth response routing',84),
('RH-CHAIN-163',{'cache','oauth'},'cache inconsistency → OAuth callback/session response confusion',74),
('RH-CHAIN-164',{'cache','service-worker'},'edge cache → service-worker cache inconsistency',60),
('RH-CHAIN-165',{'ssrf','signed-url'},'server fetch primitive → signed resource binding review',72),
('RH-CHAIN-166',{'ssrf','ai-api'},'AI URL ingestion → OAST SSRF capability boundary',70),
('RH-CHAIN-167',{'api-auth','signed-url'},'object authorization gap → signed URL issuance/binding',78),
('RH-CHAIN-168',{'api-auth','graphql'},'API auth signal → GraphQL resolver/object matrix',80),
('RH-CHAIN-169',{'api-auth','grpc-web'},'API auth signal → gRPC-Web method/object matrix',76),
('RH-CHAIN-170',{'postmessage','payment-request'},'postMessage payment bridge → amount/session/state binding',76),
('RH-CHAIN-171',{'postmessage','webauthn'},'postMessage trust → passkey ceremony/challenge routing',70),
('RH-CHAIN-172',{'source-map','oauth'},'source-map → hidden OAuth client/callback trust map',56),
('RH-CHAIN-174',{'custom-domain','oauth'},'custom domain lifecycle → OAuth redirect/origin trust',82),
('RH-CHAIN-175',{'custom-domain','saml'},'custom domain lifecycle → SAML ACS/RelayState trust',80),
('RH-CHAIN-176',{'api-version-skew','api-auth'},'legacy API version → authorization-policy skew',82),
('RH-CHAIN-179',{'json-rpc','api-auth'},'JSON-RPC method surface → function/object authorization',74),
('RH-CHAIN-180',{'graphql','oauth'},'OAuth identity → GraphQL tenant/resolver authorization matrix',70),
('RH-CHAIN-181',{'extension-bridge','oauth'},'extension bridge → OAuth response/session capability',86),
('RH-CHAIN-182',{'oauth-web-message','postmessage'},'OAuth web_message → receiver/source/origin binding',90),
('RH-CHAIN-183',{'nextjs-rsc','api-auth'},'Next.js server action/RSC → action authorization matrix',76),
('RH-CHAIN-184',{'trpc','api-auth'},'tRPC procedure surface → role/object authorization matrix',74),
('RH-CHAIN-185',{'hasura','api-auth'},'Hasura role/header surface → row/field authorization matrix',80),
('RH-CHAIN-186',{'postgrest','api-auth'},'PostgREST surface → row-level-policy authorization matrix',80),
('RH-CHAIN-187',{'persisted-graphql','cache'},'persisted GraphQL identifier → cache key/auth context review',70),
('RH-CHAIN-189',{'saml-relaystate','redirect'},'RelayState → destination/open-redirect binding',78),
]
FAMILIES=['xss','oauth','cors','api-auth','cache','ssrf','graphql','postmessage','recovery','signed-url','service-worker','websocket']
for i,a in enumerate(FAMILIES):
    for b in FAMILIES[i+1:]:
        if len(RULES)>=133:break
        RULES.append((f'RH-CHAIN-{200+len(RULES):03d}',{a,b},f'{a} primitive → {b} trust-boundary correlation review',50))
    if len(RULES)>=133:break

def generate(inventory,evidence):
    ev=defaultdict(list)
    for e in evidence:
        h=(urlparse(e.get('url','')).hostname or e.get('host','')).lower()
        if h:ev[h].append(e)
    out=[]
    for host,data in inventory.items():
        s={str(x).lower() for x in data.get('surfaces',[])}
        for e in ev.get(host,[]):
            f=e.get('family','').lower();s.add({'postmessage':'postmessage','redirect':'redirect','api-auth':'api-auth','cache':'cache','ssrf':'ssrf','cors':'cors','graphql':'graphql','xss':'xss'}.get(f,f))
        for cid,req,title,base in RULES:
            if req<=s:
                bonus=min(12,max([int(x.get('confidence_score',0)) for x in ev.get(host,[])],default=0)//10)
                out.append({'id':cid,'title':title,'host':host,'score':min(100,base+bonus),'signals':sorted(req),'state':'hypothesis','gate':['Prove each arrow independently with controlled data/accounts','Stop if next arrow requires unrelated-user data or collateral impact'],'negative_controls':['fresh baseline','nearby wrong identifier/origin','fresh session/cache key']})
    return sorted(out,key=lambda x:x['score'],reverse=True)
