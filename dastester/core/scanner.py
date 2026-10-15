"""The scan orchestrator: crawl, then run checks, then collect findings."""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from .config import ScanConfig
from .http_client import HttpClient
from .crawler import Crawler
from ..checks import registry, PASSIVE, ACTIVE, AGGRESSIVE
from ..models import Finding, Severity


@dataclass
class ScanContext:
    config: ScanConfig
    http: HttpClient
    pages: dict = field(default_factory=dict)  # url -> PageInfo (cross-page checks)


@dataclass
class ScanResult:
    config: ScanConfig
    started: str
    finished: str
    pages_scanned: int
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def duration(self) -> str:
        return f"{self.started} -> {self.finished}"

    def by_severity(self):
        counts = {s.label: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.label] += 1
        return counts


class Scanner:
    def __init__(self, config: ScanConfig, logger: Optional[Callable] = None):
        self.config = config
        self.log = logger or (lambda m: None)
        self.http = HttpClient(config)
        self.ctx = ScanContext(config=config, http=self.http)

    def run(self) -> ScanResult:
        started = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
        errors: List[str] = []

        self.log("Starting crawl...")
        crawler = Crawler(self.config, self.http, logger=self.log)
        pages = crawler.crawl()
        self.ctx.pages = pages
        self.log(f"Crawl complete: {len(pages)} page(s) in scope.")

        # Instantiate checks.
        passive_checks = [c() for c in registry if c.kind == PASSIVE]
        active_checks = [c() for c in registry if c.kind == ACTIVE]
        aggressive_checks = [c() for c in registry if c.kind == AGGRESSIVE]

        if not (self.config.active and self.config.authorized):
            if self.config.active and not self.config.authorized:
                self.log("Active checks skipped: authorisation not confirmed.")
            active_checks = []
            aggressive_checks = []
        elif not self.config.aggressive:
            if aggressive_checks:
                self.log("Aggressive checks skipped: pass --aggressive to enable.")
            aggressive_checks = []
        else:
            self.log("AGGRESSIVE MODE: running checks that may disrupt live traffic.")

        all_checks = passive_checks + active_checks + aggressive_checks
        self.log(
            f"Running {len(passive_checks)} passive, "
            f"{len(active_checks)} active, and "
            f"{len(aggressive_checks)} aggressive check(s)."
        )

        findings: List[Finding] = []
        seen_fp = set()
        for page in pages.values():
            for check in all_checks:
                try:
                    for f in check.run(page, self.ctx) or []:
                        fp = f.fingerprint()
                        if fp in seen_fp:
                            continue
                        seen_fp.add(fp)
                        findings.append(f)
                except Exception as exc:  # a check must never kill the scan
                    errors.append(f"{check.id} on {page.url}: {exc}")

        findings.sort(key=lambda f: (-int(f.severity), f.owasp, f.title))
        finished = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
        self.log(f"Scan complete: {len(findings)} finding(s).")
        return ScanResult(
            config=self.config,
            started=started,
            finished=finished,
            pages_scanned=len(pages),
            findings=findings,
            errors=errors,
        )
