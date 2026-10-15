"""Active-lite check: dangerous HTTP methods enabled.

Sends a single OPTIONS request per host root and inspects the Allow
header for risky methods (PUT, DELETE, TRACE, CONNECT). TRACE is
additionally confirmation of possible Cross-Site Tracing. This is a
read-only probe (OPTIONS) and runs once per origin.
"""

from urllib.parse import urlparse

from ..base import BaseCheck, ACTIVE
from ...models import Finding, Severity, Confidence

_RISKY = {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}


class HttpMethodsCheck(BaseCheck):
    id = "http-methods"
    name = "Dangerous HTTP methods"
    kind = ACTIVE
    owasp = "A05"
    stride = ["T", "E"]

    _probed = set()

    def run(self, page, ctx):
        findings = []
        p = urlparse(page.url)
        root = f"{p.scheme}://{p.netloc}/"
        if root in self._probed:
            return findings
        self._probed.add(root)

        resp = ctx.http.request("OPTIONS", root)
        if resp is None:
            return findings
        allow = resp.headers.get("Allow", "") or resp.headers.get("Access-Control-Allow-Methods", "")
        methods = {m.strip().upper() for m in allow.split(",") if m.strip()}
        risky = methods & _RISKY
        if risky:
            sev = Severity.MEDIUM if "TRACE" in risky or "PUT" in risky else Severity.LOW
            findings.append(Finding(
                title=f"Risky HTTP methods enabled: {', '.join(sorted(risky))}",
                severity=sev,
                description=(
                    f"The server advertises support for {', '.join(sorted(risky))} "
                    "on the root path. Methods such as PUT/DELETE/TRACE can enable "
                    "unauthorised changes or Cross-Site Tracing."
                ),
                url=root,
                owasp="A05",
                stride=["T", "E"],
                cwe="CWE-650",
                confidence=Confidence.MEDIUM,
                evidence=f"Allow: {allow[:120]}",
                remediation=(
                    "Disable unused HTTP methods at the web server; restrict "
                    "write methods to authenticated APIs only."
                ),
                reference="https://owasp.org/www-project-web-security-testing-guide/",
                check_id=self.id,
            ))
        return findings
