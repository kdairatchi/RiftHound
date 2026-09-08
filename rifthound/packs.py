PACKS={
'RECON':'''subfinder -d target.com -silent | sort -u > subdomains.txt\namass enum -passive -d target.com | sort -u >> subdomains.txt\nhttpx -l subdomains.txt -silent -j -sc -ct -title -server -td -cdn -location -o httpx.jsonl\nkatana -list live.txt -silent -d 3 -jc -kf robotstxt,sitemapxml -fx\ngau --subs target.com | sort -u > gau.txt''',
'PM':'''rg -n -S "addEventListener\\(['\\\"]message|onmessage\\s*=|postMessage\\(|event\\.origin|event\\.source|MessageChannel|BroadcastChannel|window\\.name" js/''',
'XSS':'''cat urls.txt | gf xss | sort -u > gf-xss.txt\ncat gf-xss.txt | kxss | tee kxss.txt\ncat gf-xss.txt | Gxss -p RIFTHOUND -c 20 | tee gxss.txt\ndalfox scan gf-xss.txt --format jsonl --output dalfox.jsonl''',
'OAUTH':'''rg -n -S "redirect_uri|response_type|response_mode|code_verifier|code_challenge|state=|nonce=|id_token|access_token|web_message|postMessage" js/''',
'CORS':'''curl -kisS https://target.example/api -H 'Origin: https://attacker.invalid' | sed -n '1,30p'\ncurl -kisS https://target.example/api -H 'Origin: null' | sed -n '1,30p' ''',
'IDOR':'''rg -n -S "owner(_id)?|tenant(_id)?|organization(_id)?|account(_id)?|user(_id)?|role|permissions|invite|reset|recovery|mfa|api[_-]?key" js/ openapi/ graphql/''',
'CACHE':'''curl -kisS 'https://target.example/path?cb=RH1' | rg -i '^(cache-control|age|vary|via|x-cache|cf-cache-status|etag|location):' ''',
'SSRF':'''# OAST-first only. Use one URL-like parameter and a unique collaborator label; do not probe private IP/cloud metadata without explicit authorization.''',
'GRAPHQL':'''curl -sS https://target.example/graphql -H 'content-type: application/json' --data '{"query":"{__typename}"}' | jq .''',
'FALSE-POSITIVE':'''# 1 baseline absent  2 isolate one input  3 fresh canary  4 counterfactual control  5 fresh session/cache key  6 second independent signal''',
'BYPASS-VARIANTS':'''# Test normalization one dimension at a time: exact → encoded → dot segment; exact Origin → sibling/suffix/trailing-dot/null; HPP A,B vs B,A. Avoid indiscriminate WAF spraying.''',
'NUCLEI-AI':'''nuclei -l urls.txt -ai 'Create a low-impact template using a harmless unique canary, baseline negative control and deterministic matchers. No destructive actions or unrelated-user data.' -rl 5''',
'SERVER':'''# Use arithmetic-only SSTI, SQL error differentials, inert CRLF header canaries, traversal differentials and OAST-only SSRF.''',
'REALTIME':'''rg -n -S "WebSocket|EventSource|WebTransport|socket.io|subscription" js/''',
'RECOVERY':'''rg -n -S "password.?reset|recovery|mfa|2fa|invite|magic.?link|session.?revoke" js/''',
'WORDPRESS':'''curl -sS https://target.example/wp-json/ | jq '.namespaces'\nrg -n -S "wp_ajax_|register_rest_route|permission_callback|current_user_can" plugin-src/''',
}
# Alias/fill command families for ergonomic packs.
for n in ['CSRF','CMDI','DESYNC','API','AUTH','JWT','SAML','UPLOAD','RACE','PROTO','SERVICEWORKER','GRPC','HOST','BUSINESS','WEBHOOK','XXE','MODERN','GF','ARJUN','DALFOX','KXSS','GXSS','WAYMORE','HTTPX-FP','NUCLEI-AUTO','XSS-QUORUM']:
 PACKS.setdefault(n,PACKS.get('SERVER' if n in {'CMDI','XXE','UPLOAD'} else 'RECON' if n in {'WAYMORE','HTTPX-FP'} else 'XSS' if n in {'DALFOX','KXSS','GXSS','XSS-QUORUM'} else 'API',' # See README methodology and use low-impact validation gates.'))
