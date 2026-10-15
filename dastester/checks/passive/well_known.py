"""Active-lite check: security.txt and robots.txt hygiene (informational).

Fetches /.well-known/security.txt and /robots.txt once per origin.
Absence of security.txt is informational; robots.txt entries that
disclose sensitive paths are flagged low. Read-only GETs, once per host.
"""

from urllib.parse import urljoin, urlparse

from ..base import BaseCheck, ACTIVE
from ...models import Finding, Severity, Confidence

_SENSITIVE_ROBOT_HINTS = ("admin", "backup", "config", "private", "secret",
                          "internal", "test", "staging", ".git", "db")


class WellKnownCheck(BaseCheck):
    id = "well-known"
    name = "security.txt and robots.txt"
    kind = ACTIVE
    owasp = "A05"
    stride = ["I"]

    _probed = set()

    def run(self, page, ctx):
        findings = []
        p = urlparse(page.url)
        root = f"{p.scheme}://{p.netloc}/"
        if root in self._probed:
            return findings
        self._probed.add(root)

        sec = ctx.http.get(urljoin(root, ".well-known/security.txt"))
        if sec is None or sec.status != 200:
            findings.append(Finding(
                title="No security.txt published",
                severity=Severity.INFO,
                description=(
                    "No /.well-known/security.txt was found. Publishing one "
                    "gives researchers a clear channel to report issues."
                ),
                url=urljoin(root, ".well-known/security.txt"),
                owasp="A05",
                stride=["I"],
                cwe=None,
                confidence=Confidence.HIGH,
                evidence="GET /.well-known/security.txt did not return 200.",
                remediation="Publish a security.txt per RFC 9116.",
                reference="https://www.rfc-editor.org/rfc/rfc9116",
                check_id=self.id,
            ))

        robots = ctx.http.get(urljoin(root, "robots.txt"))
        if robots and robots.status == 200 and robots.text:
            disclosed = []
            for line in robots.text.splitlines():
                line = line.strip().lower()
                if line.startswith("disallow:") and any(
                    h in line for h in _SENSITIVE_ROBOT_HINTS
                ):
                    disclosed.append(line)
            if disclosed:
                findings.append(Finding(
                    title="robots.txt discloses sensitive paths",
                    severity=Severity.LOW,
                    description=(
                        "robots.txt lists Disallow entries that point to "
                        "potentially sensitive locations, giving attackers a map."
                    ),
                    url=urljoin(root, "robots.txt"),
                    owasp="A05",
                    stride=["I"],
                    cwe="CWE-200",
                    confidence=Confidence.MEDIUM,
                    evidence="; ".join(disclosed[:4]),
                    remediation=(
                        "Do not rely on robots.txt for security; protect "
                        "sensitive paths with authentication/authorisation."
                    ),
                    reference="https://owasp.org/www-project-web-security-testing-guide/",
                    check_id=self.id,
                ))
        return findings
