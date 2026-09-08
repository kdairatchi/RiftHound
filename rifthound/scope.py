from __future__ import annotations
import re
from urllib.parse import urlparse, urlunparse

def normalize_host(value: str) -> str:
    value=(value or '').strip().lower().rstrip('.')
    if '://' in value:
        value=(urlparse(value).hostname or '').lower().rstrip('.')
    return value

def host_in_roots(host: str, roots: list[str]) -> bool:
    host=normalize_host(host)
    return any(host==normalize_host(r) or host.endswith('.'+normalize_host(r)) for r in roots if normalize_host(r))

def url_in_scope(url: str, roots: list[str], include_hosts=None, exclude_hosts=None, exclude_regex=None) -> bool:
    try: host=normalize_host(urlparse(url).hostname or '')
    except Exception: return False
    if not host: return False
    includes=[normalize_host(x) for x in (include_hosts or []) if normalize_host(x)]
    excludes=[normalize_host(x) for x in (exclude_hosts or []) if normalize_host(x)]
    if roots and not host_in_roots(host, roots) and host not in includes: return False
    if any(host==x or host.endswith('.'+x) for x in excludes): return False
    if any(re.search(p,url,re.I) for p in (exclude_regex or [])): return False
    return True

def normalize_url(url: str, require_https=False) -> str|None:
    url=(url or '').strip()
    if not url: return None
    if '://' not in url:
        url='https://'+url
    p=urlparse(url)
    if p.scheme not in {'http','https'} or not p.hostname: return None
    scheme='https' if require_https else p.scheme.lower()
    return urlunparse((scheme,p.netloc,p.path or '/',p.params,p.query,''))
