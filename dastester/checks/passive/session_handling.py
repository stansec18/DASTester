"""Passive check: session handling hygiene.

Reviews session cookies for issues beyond the Secure/HttpOnly/SameSite
flags already covered by the cookie check: overly long or missing
lifetimes, session identifiers exposed in the URL, and tokens placed in
persistent cookies. Reads crawl output only.
"""

import re
from urllib.parse import urlparse, parse_qs

from ..base import BaseCheck, PASSIVE
from ...models import Finding, Severity, Confidence

_SESSION_HINTS = ("sess", "sid", "auth", "token", "jwt", "phpsessid", "jsessionid")


class SessionHandlingCheck(BaseCheck):
    id = "session-handling"
    name = "Session handling hygiene"
    kind = PASSIVE
    owasp = "A07"
    stride = ["S", "E"]

    def run(self, page, ctx):
        findings = []

        # Session identifier in the URL (query string).
        qs = parse_qs(urlparse(page.url).query)
        for param in qs:
            if any(h in param.lower() for h in _SESSION_HINTS):
                findings.append(Finding(
                    title=f"Possible session identifier in URL ('{param}')",
                    severity=Severity.MEDIUM,
                    description=(
                        "A session-like identifier appears in the URL query "
                        "string, where it can leak via logs, history, and the "
                        "Referer header."
                    ),
                    url=page.url,
                    owasp="A07",
                    stride=["S", "I"],
                    cwe="CWE-598",
                    confidence=Confidence.LOW,
                    evidence=f"URL parameter: {param}",
                    remediation="Carry session identifiers in cookies, not URLs.",
                    reference="https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url",
                    check_id=self.id,
                ))

        # Persistent session cookie (has Expires/Max-Age far in the future).
        for k, v in page.headers.items():
            if k.lower() != "set-cookie":
                continue
            low = v.lower()
            name = v.split("=", 1)[0].strip().lower()
            if not any(h in name for h in _SESSION_HINTS):
                continue
            m = re.search(r"max-age=(\d+)", low)
            if ("expires=" in low or m) and m and int(m.group(1)) > 86400:
                findings.append(Finding(
                    title=f"Session cookie '{name}' has a long persistent lifetime",
                    severity=Severity.LOW,
                    description=(
                        "A session cookie is persisted for a long period "
                        "(> 24h), widening the window for session hijacking."
                    ),
                    url=page.url,
                    owasp="A07",
                    stride=["S"],
                    cwe="CWE-613",
                    confidence=Confidence.LOW,
                    evidence=f"Set-Cookie: {v[:120]}",
                    remediation=(
                        "Prefer short-lived session cookies; use idle and "
                        "absolute timeouts and regenerate IDs after login."
                    ),
                    reference="https://owasp.org/www-community/attacks/Session_hijacking_attack",
                    check_id=self.id,
                ))
        return findings
