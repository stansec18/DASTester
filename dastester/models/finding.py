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

    @classmethod
    def from_name(cls, name: str) -> "Severity":
        return cls[name.strip().upper()]


class Confidence(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    @property
    def label(self) -> str:
        return self.name.capitalize()


@dataclass
class Finding:
    """A single security observation produced by a check."""

    title: str
    severity: Severity
    description: str
    # Where it was found.
    url: str
    # Classification.
    owasp: str = "A05"                 # OWASP Top 10 category key, e.g. "A05"
    stride: List[str] = field(default_factory=list)  # STRIDE codes, e.g. ["I"]
    cwe: Optional[str] = None          # e.g. "CWE-693"
    # Supporting detail.
    confidence: Confidence = Confidence.MEDIUM
    evidence: str = ""                 # short, non-sensitive supporting evidence
    remediation: str = ""              # how to fix it
    reference: str = ""                # external reference URL
    check_id: str = ""                 # the check that produced this finding

    def fingerprint(self) -> str:
        """Stable id used to de-duplicate findings."""
        raw = f"{self.check_id}|{self.title}|{self.url}|{self.owasp}"
        return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.label
        d["severity_rank"] = int(self.severity)
        d["confidence"] = self.confidence.label
        d["fingerprint"] = self.fingerprint()
        return d
