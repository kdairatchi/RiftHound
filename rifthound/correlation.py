"""Conservative service-version correlation; catalog results are leads, never proof."""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path


def nmap_services(path: Path) -> list[dict]:
    """Return discovered service banners from an Nmap XML report."""
    if not path.exists():
        return []
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        return []
    rows = []
    for host in root.findall('host'):
        address = next((a.get('addr', '') for a in host.findall('address') if a.get('addrtype') in {'ipv4', 'ipv6'}), '')
        for port in host.findall('./ports/port'):
            if port.find("state[@state='open']") is None:
                continue
            service = port.find('service')
            if service is None:
                continue
            parts = [service.get(key, '') for key in ('product', 'version', 'extrainfo')]
            label = ' '.join(item for item in parts if item).strip()
            if label:
                rows.append({'host': address, 'port': int(port.get('portid', '0')), 'protocol': port.get('protocol', ''), 'service': service.get('name', ''), 'product': service.get('product', ''), 'version': service.get('version', ''), 'label': label})
    return rows


def searchsploit_results(text: str) -> list[dict]:
    """Parse Searchsploit JSON without treating a database match as a finding."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    return [
        {'edb_id': row.get('EDB-ID', ''), 'title': row.get('Title', ''), 'path': row.get('Path', ''), 'codes': row.get('Codes', ''), 'cves': sorted(set(re.findall(r'CVE-\d{4}-\d{4,}', ' '.join(map(str, (row.get('Codes', ''), row.get('Title', '')))), re.I))) }
        for row in data.get('RESULTS_EXPLOIT', [])
        if isinstance(row, dict)
    ]


def metasploit_query(service: dict) -> str:
    """Create a bounded local-catalog query from an observed product/version."""
    query = ' '.join(filter(None, (service.get('product'), service.get('version'))))
    return re.sub(r'[^A-Za-z0-9._ -]', '', query).strip()[:120]
