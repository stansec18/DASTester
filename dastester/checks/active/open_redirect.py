"""Active check: open redirect surface.

Detection approach: for parameters whose name or value looks like a
redirect target, substitute a benign, scope-external canary host and
check whether the server issues a redirect (Location header) to it.
DASTester uses allow_redirects=False here so it never actually follows the
redirect off-scope.
"""

from urllib.parse import urlparse

from ..base import BaseCheck, ACTIVE
from ...models import Finding, Severity, Confidence
from ._util import iter_param_mutations, set_param

_REDIRECT_HINTS = ("url", "next", "redirect", "return", "returnurl", "dest",
                   "destination", "continue", "to", "goto", "r", "u")
# A benign canary that is clearly not the target; never fetched.
_CANARY = "https://dastester-canary.invalid/"


class OpenRedirectCheck(BaseCheck):
    id = "open-redirect"
    name = "Open redirect surface"
    kind = ACTIVE
    owasp = "A01"
    stride = ["S", "T"]

    def run(self, page, ctx):
        findings = []
        if "?" not in page.url:
            return findings
        seen = set()
        for name, _ in iter_param_mutations(page.url, ""):
            if name in seen:
                continue
            seen.add(name)
            if name.lower() not in _REDIRECT_HINTS:
                continue
            target = set_param(page.url, name, _CANARY)
            resp = ctx.http.get(target, allow_redirects=False)
            if resp is None:
                continue
            location = resp.headers.get("Location", "")
            if location.startswith(_CANARY) or "dastester-canary.invalid" in location:
                findings.append(Finding(
                    title=f"Open redirect via parameter '{name}'",
                    severity=Severity.MEDIUM,
                    description=(
                        f"The '{name}' parameter controls the redirect target "
                        "without validation, allowing redirection to an "
                        "attacker-chosen external site (phishing / token theft "
                        "pivot)."
                    ),
                    url=page.url,
                    owasp="A01",
                    stride=["S", "T"],
                    cwe="CWE-601",
                    confidence=Confidence.HIGH,
                    evidence=f"Location header redirected to canary: {location[:120]}",
                    remediation=(
                        "Validate redirect targets against an allow-list of "
                        "relative paths or known hosts; reject absolute external "
                        "URLs."
                    ),
                    reference="https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet",
                    check_id=self.id,
                ))
        return findings
