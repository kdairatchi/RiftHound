"""Scope-filtered import of Reconner recon artifacts."""
from __future__ import annotations

import json
from pathlib import Path
from .scope import normalize_url,url_in_scope

SOURCES={'katana.txt':'katana','gau.txt':'gau','wayback.txt':'wayback','live.txt':'live','raw.txt':'raw','validated.txt':'validated','js_endpoints.txt':'js-endpoints','param.txt':'parameters'}

def import_artifacts(directory, roots, scope=None):
    base=Path(directory)
    if not base.is_dir():raise ValueError(f'Reconner output directory not found: {base}')
    scope=scope or {};urls=[];sources={}
    for filename,label in SOURCES.items():
        path=base/filename
        if not path.is_file():continue
        kept=[]
        for line in path.read_text(errors='replace').splitlines():
            if any(char in line for char in "'\"<>{}\\\\") or any(char.isspace() for char in line):
                continue
            url=normalize_url(line.strip())
            if url and url_in_scope(url,roots,scope.get('include_hosts'),scope.get('exclude_hosts'),scope.get('exclude_regex')):kept.append(url)
        sources[label]=len(set(kept));urls.extend(kept)
    return {'directory':str(base.resolve()),'sources':sources,'urls':list(dict.fromkeys(urls))}
