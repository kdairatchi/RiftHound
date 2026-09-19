# RiftHound v3.0.1

## Unreleased

- Added opt-in BBOT passive subdomain enumeration with scope-filtered JSON import.
- Added opt-in service-version correlation: bounded Naabu discovery, Nmap `-sV --version-light`, and local Searchsploit/Metasploit catalog searches.
- Added opt-in `--nmap-vuln`, excluding NSE scripts tagged exploit, intrusive, DoS, or brute force.
- Catalog matches are explicitly recorded as triage leads; RiftHound does not execute exploit modules or retrieve PoCs.

Initial GitHub release by **kdairatchi**.

- Four phase workflow
- 130 contiguous methodology steps
- 12 presets
- Native reflection/DOM/CORS/redirect/SQL-error/SSTI/CRLF/OAuth/header checks
- Cross-tool evidence quorum
- Modern browser/API fingerprints
- 133 chain hypothesis rules
- Nuclei AI prompt profiles
- HTML/Markdown/JSON reporting
- Scope enforcement and safety gates
