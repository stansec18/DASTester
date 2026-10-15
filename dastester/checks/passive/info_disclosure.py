"""Passive check: information disclosure in headers and bodies."""

import re

from ..base import BaseCheck, PASSIVE
from ...models import Finding, Severity, Confidence

_VERSION_HEADERS = ("server", "x-powered-by", "x-aspnet-version",
                    "x-aspnetmvc-version", "x-generator")

# Signatures that suggest a verbose error / stack trace leaked to the client.
_ERROR_SIGNATURES = (
    "Traceback (most recent call last)",
    "Warning: ",
    "Fatal error:",
    "Exception in thread",
    "java.lang.",
    "at org.springframework",
    "System.Web.",
    "ORA-0",
    "SQLSTATE[",
    "You have an error in your SQL syntax",
)


class InfoDisclosureCheck(BaseCheck):
    id = "info-disclosure"
    name = "Information disclosure"
    kind = PASSIVE
    owasp = "A05"
    stride = ["I"]

    def run(self, page, ctx):
        findings = []
        headers = {k.lower(): v for k, v in page.headers.items()}

        for h in _VERSION_HEADERS:
            if h in headers and re.search(r"\d", headers[h]):
                findings.append(Finding(
                    title=f"Version information disclosed in '{h}' header",
                    severity=Severity.LOW,
                    description=(
                        f"The '{h}' header reveals software and version "
                        "information that aids an attacker in fingerprinting."
                    ),
                    url=page.url,
                    owasp="A06",
                    stride=["I"],
                    cwe="CWE-200",
                    confidence=Confidence.HIGH,
                    evidence=f"{h}: {headers[h][:120]}",
                    remediation="Suppress or genericise version banners in responses.",
                    reference="https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
                    check_id=self.id,
                ))

        body = page.body or ""
        for sig in _ERROR_SIGNATURES:
            if sig in body:
                findings.append(Finding(
                    title="Verbose error / stack trace disclosed",
                    severity=Severity.MEDIUM,
                    description=(
                        "The response body contains error output or a stack "
                        "trace, which can reveal internal paths, queries, or "
                        "component versions."
                    ),
                    url=page.url,
                    owasp="A05",
                    stride=["I"],
                    cwe="CWE-209",
                    confidence=Confidence.MEDIUM,
                    evidence=f"Matched signature: {sig!r}",
                    remediation=(
                        "Return generic error pages to clients and log details "
                        "server-side only."
                    ),
                    reference="https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                    check_id=self.id,
                ))
                break
        return findings
