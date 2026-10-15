"""Scan configuration and scope control.

Scope control is a first-class concern: DASTester will only ever send
requests to hosts that fall inside the configured scope, derived from the
target URL(s) unless explicitly widened. This keeps an authorised test
from accidentally touching third-party systems.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Set
from urllib.parse import urlparse


@dataclass
class ScanConfig:
    targets: List[str]

    # Authorisation: the operator must affirm they are authorised to test.
    authorized: bool = False

    # Crawling.
    max_depth: int = 2
    max_pages: int = 200
    include_subdomains: bool = False

    # Active (request-sending) checks. Passive checks always run.
    active: bool = True
    # Aggressive checks (request smuggling, aggressive SSRF). Off by default;
    # require both authorisation and this flag.
    aggressive: bool = False

    # Politeness / safety.
    rate_limit: float = 5.0        # max requests per second
    timeout: float = 15.0
    max_retries: int = 2
    user_agent: str = "DASTester/1.0 (+authorised security testing)"
    verify_tls: bool = True        # verify certs; findings still note TLS issues

    # Scope.
    in_scope_hosts: Set[str] = field(default_factory=set)
    extra_scope_hosts: Set[str] = field(default_factory=set)

    # Auth to the target (optional) — passed straight to requests.
    headers: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)

    # Access-control (IDOR/BOLA/BFLA) differential testing config (optional).
    # See dastester/checks/aggressive/access_control.py for the schema.
    access_control: dict = field(default_factory=dict)

    # Output.
    output_dir: str = "reports"
    report_name: str = "dastester-report"
    formats: List[str] = field(default_factory=lambda: ["html", "pdf"])

    def __post_init__(self):
        for t in self.targets:
            host = urlparse(t).hostname
            if host:
                self.in_scope_hosts.add(host.lower())
        self.in_scope_hosts |= {h.lower() for h in self.extra_scope_hosts}

    def in_scope(self, url: str) -> bool:
        host = (urlparse(url).hostname or "").lower()
        if not host:
            return False
        if host in self.in_scope_hosts:
            return True
        if self.include_subdomains:
            return any(
                host == base or host.endswith("." + base)
                for base in self.in_scope_hosts
            )
        return False
