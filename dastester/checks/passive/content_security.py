"""Passive check: mixed content and CSP quality."""

import re

from ..base import BaseCheck, PASSIVE
from ...models import Finding, Severity, Confidence


class ContentSecurityCheck(BaseCheck):
    id = "content-security"
    name = "Mixed content and CSP quality"
    kind = PASSIVE
    owasp = "A05"
    stride = ["T", "I"]

    def run(self, page, ctx):
        findings = []
        headers = {k.lower(): v for k, v in page.headers.items()}

        # Mixed content: HTTPS page loading HTTP subresources.
        if page.url.lower().startswith("https://") and page.body:
            http_refs = re.findall(
                r'(?:src|href)\s*=\s*["\'](http://[^"\']+)', page.body, re.I
            )
            if http_refs:
                findings.append(Finding(
                    title="Mixed content: HTTP resources on an HTTPS page",
                    severity=Severity.LOW,
                    description=(
                        "An HTTPS page references subresources over plaintext "
                        "HTTP, which can be intercepted or stripped."
                    ),
                    url=page.url,
                    owasp="A02",
                    stride=["T", "I"],
                    cwe="CWE-311",
                    confidence=Confidence.HIGH,
                    evidence="; ".join(http_refs[:3]),
                    remediation="Load all subresources over HTTPS.",
                    reference="https://developer.mozilla.org/docs/Web/Security/Mixed_content",
                    check_id=self.id,
                ))

        # Weak CSP: unsafe-inline / wildcard.
        csp = headers.get("content-security-policy", "")
        if csp:
            weaknesses = []
            if "unsafe-inline" in csp:
                weaknesses.append("'unsafe-inline'")
            if "unsafe-eval" in csp:
                weaknesses.append("'unsafe-eval'")
            if re.search(r"(?:default|script)-src[^;]*\*", csp):
                weaknesses.append("wildcard source")
            if weaknesses:
                findings.append(Finding(
                    title="Weak Content-Security-Policy directives",
                    severity=Severity.LOW,
                    description=(
                        "The CSP contains directives that substantially reduce "
                        f"its protective value: {', '.join(weaknesses)}."
                    ),
                    url=page.url,
                    owasp="A05",
                    stride=["T"],
                    cwe="CWE-693",
                    confidence=Confidence.MEDIUM,
                    evidence=csp[:160],
                    remediation=(
                        "Remove 'unsafe-inline'/'unsafe-eval' and wildcard "
                        "sources; use nonces or hashes for inline scripts."
                    ),
                    reference="https://owasp.org/www-project-secure-headers/",
                    check_id=self.id,
                ))
        return findings
