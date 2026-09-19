# Service correlation, without automatic exploitation

Use this feature only where you have clear authorization for service discovery and version detection:

```bash
rifthound example.com --service-correlation -p balanced
```

RiftHound first asks Naabu for the top 100 TCP ports on the in-scope hosts it already discovered. Nmap then runs `-sV --version-light` against only those observed ports. This keeps the service check bounded; it is not a full-port scan.

For every product/version banner Nmap returns, RiftHound searches the local Searchsploit database and the local Metasploit module catalog. Those searches do not run a module, launch a payload, or copy a public proof of concept. The results are saved in `artifacts/service-correlation/version-correlation.json`.

Treat every match as a research lead. Banners can be stale, altered by a proxy, or unrelated to the vulnerable component. Before reporting anything, confirm the exact version, affected configuration, reachable attack path, program scope, and a harmless controlled impact. The report artifact repeats this warning so it is not lost when findings are shared.

## Optional Nmap vulnerability checks

Add `--nmap-vuln` when the program permits active NSE checks. It runs only on the ports Naabu already observed and uses the selector `vuln and not (intrusive or exploit or dos or brute)`. This deliberately excludes scripts that Nmap classifies as exploit, intrusive, denial-of-service, or brute force. The script output is saved alongside the other correlation evidence and remains an unvalidated candidate.
