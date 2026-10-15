"""The Finding data model shared across checks and reporting."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import List, Optional


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.capitalize()


class Confidence(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    @property
    def label(self) -> str:
        return self.name.capitalize()


@dataclass
class Finding:
    title: str
    severity: Severity
    description: str
    url: str
    owasp: str = "A05:2021"
    stride: List[str] = field(default_factory=list)
    cwe: Optional[str] = None
    cve: Optional[str] = None
    attack_vector: str = "Network"
    exploitability: str = "Easy"
    auth_required: str = "No"
    confidence: Confidence = Confidence.MEDIUM
    evidence: str = ""
    remediation: str = ""
    reference: str = ""
    check_id: str = ""

    def fingerprint(self) -> str:
        raw = f"{self.check_id}|{self.title}|{self.url}|{self.owasp}"
        return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.label
        d["severity_rank"] = int(self.severity)
        d["confidence"] = self.confidence.label
        d["fingerprint"] = self.fingerprint()
        return d
