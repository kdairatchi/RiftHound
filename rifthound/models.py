from __future__ import annotations
from dataclasses import dataclass, asdict, field
from typing import Any

@dataclass
class Finding:
    family: str
    title: str
    url: str
    severity: str = 'info'
    confidence: str = 'candidate'
    parameter: str = ''
    method: str = 'GET'
    evidence: dict[str, Any] = field(default_factory=dict)
    evidence_gate: list[str] = field(default_factory=list)
    negative_controls: list[str] = field(default_factory=list)
    false_positive_flags: list[str] = field(default_factory=list)
    score: int = 0
    report_state: str = 'lead'
    tools: list[str] = field(default_factory=lambda: ['native'])

    def to_dict(self):
        return asdict(self)
