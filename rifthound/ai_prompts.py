PROMPTS={
'reflection':'Create a low-impact Nuclei template for attributable reflected input. Use a unique harmless canary, baseline negative control, one input at a time, and deterministic matchers. Do not execute JavaScript, steal credentials, brute force, or make destructive changes.',
'xss-context':'Create a non-executing XSS context triage template. Prove isolated reflection then classify inert metacharacter survival. Do not execute script or read cookies/tokens.',
'cors':'Create a low-impact CORS template using attacker.invalid and null Origin controls. Distinguish wildcard ACAO from arbitrary-origin reflection. Do not access unrelated user data.',
'oauth-metadata':'Create a passive OAuth/OIDC discovery template for issuer, endpoints, PKCE, PAR/device/revocation/logout and response modes. Do not redeem codes or replay tokens.',
'oauth-redirect':'Create a conservative OAuth redirect validation template comparing exact URI with one normalization variant at a time. Do not capture unrelated-user codes.',
'cache':'Create a conservative cache-behavior template with unique cache-busters and harmless header/query canaries. Do not poison shared caches.',
'graphql':'Create a low-impact GraphQL detector using __typename and GraphQL response structure. Do not enumerate private objects or abuse batching.',
'openapi':'Create a passive OpenAPI/Swagger discovery template. Do not execute state-changing operations.',
'headers':'Create a low-impact header influence template, one header canary at a time, with baseline and negative control.',
'crlf':'Create a low-impact CRLF validator using an inert unique response-header canary. Do not set cookies or executable content.',
'ssti':'Create an arithmetic-only SSTI detector with randomized wrappers. Do not execute commands or read files/env.',
'sqli-errors':'Create a conservative SQL error/differential detector using quote and paired-quote controls. No UNION/time delays/data extraction.',
'ssrf-oast':'Create an OAST-only SSRF detector using caller-controlled collaborator labels. Do not probe localhost/private IP/cloud metadata.',
'wordpress':'Create passive WordPress fingerprint templates for core/plugin/theme clues, REST namespaces, AJAX actions and metadata. Do not exploit plugins.',
'modern-browser':'Create passive detectors for Trusted Types, CSP, COOP/COEP/CORP, service workers, WebAuthn, WebTransport, BroadcastChannel, MessageChannel and extension bridges.'
}
