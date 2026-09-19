# RiftHound v3

**A practical, evidence-first companion for authorized bug-bounty research.** It gathers leads, keeps the supporting artifacts together, and makes it clear what still needs to be proven.  
Author: **kdairatchi**

RiftHound is an authorized-security research framework that connects recon tools, careful differential checks, browser/API fingerprints, external corroboration, false-positive gates, and chain hypotheses. A lead is never presented as a confirmed vulnerability just because a scanner recognized a pattern.

```text
AUTHORIZED SCOPE
      │
      ▼
PHASE 1 — RECON          subfinder • amass • httpx • katana • gau
      │
      ▼
PHASE 2 — DISCOVERY      gf • kxss • Gxss • DOM/postMessage • parameters
      │
      ▼
PHASE 3 — VALIDATION     native differentials • Dalfox • Nuclei • optional -ai
      │
      ▼
PHASE 4 — CORRELATION    evidence quorum • FP penalties • chains • reports
```

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
pytest
rifthound doctor
rifthound example.com
```

The default `balanced` preset runs all four phases with low-impact defaults.

```bash
rifthound example.com -p quick
rifthound example.com -p deep
rifthound https://app.example.com -p client
rifthound https://api.example.com -p api
rifthound https://app.example.com -p auth
rifthound https://site.example.com -p wordpress
```

## Presets

`passive`, `quick`, `balanced`, `deep`, `full`, `xss`, `client`, `api`, `auth`, `cache`, `server`, `wordpress`.

## External adapters

RiftHound detects and uses tools when installed:

`subfinder`, `amass`, ProjectDiscovery `httpx`, `katana`, `gau`, `waymore`, `uro`, `gf`, `kxss`, `Gxss`, `dalfox`, `arjun`, `fallparams`, `nuclei`, `rg`, `curl`, `jq`.

BBOT is an optional, opt-in recon adapter. It runs only the `subdomain-enum` preset with BBOT's `passive` module requirement and consumes only in-scope JSON results:

```bash
rifthound example.com --bbot
```

## JavaScript analysis and verbose logs

Use the installed JSAttack tool as an opt-in static-analysis pass over RiftHound's scoped URL list:

```bash
rifthound example.com --jsattack -p balanced
```

It runs `jsattack analyze` with crawl depth `0`; active JSAttack probes are not enabled. Add `--verbose` to any hunt to show each subprocess exit code, output sizes, and its saved log paths. `--quiet` remains available for script-friendly output.

## Service versions and CVE research

For an explicitly authorized scope, opt into a bounded service pass:

```bash
rifthound example.com --service-correlation -p balanced
```

This uses Naabu's top 100 ports, then runs Nmap `-sV --version-light` only on observed open ports. It searches the local Searchsploit and Metasploit catalogs for the observed product/version strings. Results are written to `artifacts/service-correlation/version-correlation.json` as **triage leads**. No exploit module, payload, or public PoC is run or copied; exact version, exposure, scope, and controlled impact must still be validated.

To also run Nmap's non-intrusive vulnerability scripts on those same observed ports:

```bash
rifthound example.com --nmap-vuln -p balanced
```

Scripts tagged `exploit`, `intrusive`, `dos`, or `brute` are excluded. Their output is still a candidate, not confirmation.

Run:

```bash
rifthound doctor
```

It explicitly detects the common `httpx` binary-name collision with the Python HTTPX CLI.

## Evidence model

A scanner hit is not automatically a vulnerability.

```text
surface → candidate → strong candidate → validated primitive
        → corroborated chain → controlled impact → report candidate
```

RiftHound uses unique canaries, stable baselines, one-input isolation, negative controls, WAF/challenge and rate-limit flags, non-HTML reflection penalties, cross-tool quorum, and separate hunt-priority scoring vs CVSS.

## postMessage/client methodology

RiftHound inventories `event.origin`, `event.source`, popup/opener/parent/frame relationships, wildcard `targetOrigin`, weak substring/regex origin predicates, null/opaque origins, message schemas, `MessageChannel`, `BroadcastChannel`, `window.name`, OAuth `web_message`, service workers, Trusted Types/CSP, extension bridges, WebAuthn, WebSocket/SSE/WebTransport.

Use `scripts/browser-console.js` for a passive message observer in authorized test contexts.

## Modern surfaces

OAuth/OIDC, PKCE, OAuth web-message, SAML RelayState, OpenAPI, GraphQL/APQ, gRPC-Web, JSON-RPC, tRPC, Hasura/PostgREST, signed cloud URLs, service workers, source maps, WebAuthn, Next.js/RSC, AI/agent/MCP-style API paths and common CDN/framework fingerprints.

## Safe normalization variants

```bash
rifthound variants origin https://app.example.com
rifthound variants redirect https://app.example.com/oauth/callback
rifthound variants hpp id
rifthound variants content-type
rifthound variants cache-headers rh123
```

## Nuclei enhancement layer

```bash
export PDCP_API_KEY='...'
rifthound example.com --ai --ai-prompt reflection --ai-prompt cors
```

AI prompt profiles are low-impact and require baseline/negative controls.

## STEP-001 → STEP-130

```bash
rifthound steps
rifthound steps --json
```

The test suite verifies all 130 contiguous workflow steps.

## Command packs

```bash
rifthound packs PM
rifthound packs XSS
rifthound packs OAUTH
rifthound packs FALSE-POSITIVE
rifthound packs ALL
```

## Safety boundaries

RiftHound is for systems you own or are explicitly authorized to test. Automatic workflows intentionally do **not** perform destructive account takeover, unrelated-user token replay, private-network/cloud-metadata SSRF, request-smuggling/desync exploitation, DoS/resource exhaustion, destructive BOLA writes or irreversible financial/business-flow abuse.
