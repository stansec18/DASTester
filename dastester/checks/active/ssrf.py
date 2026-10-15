"""Active check: SSRF surface (safe tier, no internal probing).

Identifies parameters that appear to make the server fetch a URL. For
each candidate, DASTester substitutes a benign, scope-external canary URL
and looks for signals that the server performed a server-side fetch
(e.g. the response echoes fetch status/content, or timing changes).

This safe tier never targets internal/metadata addresses -- that is
reserved for the aggressive tier (ssrf_aggressive), behind --aggressive.
Reliable *blind* SSRF confirmation needs an out-of-band listener, which
DASTester reports as a recommendation rather than performing.
"""

from ..base import BaseCheck, ACTIVE
from ...models import Finding, Severity, Confidence
from ._util import iter_param_mutations, set_param

_URL_PARAM_HINTS = ("url", "uri", "link", "src", "source", "dest", "target",
                    "fetch", "load", "import", "callback", "feed", "proxy",
                    "image", "img", "file", "path", "domain", "host")
# A benign canary host that does not resolve to anything sensitive.
_CANARY = "http://dastester-ssrf-probe.invalid/ping"


class SsrfCheck(BaseCheck):
    id = "ssrf-surface"
    name = "SSRF surface (safe tier)"
    kind = ACTIVE
    owasp = "A10"
    stride = ["I", "E"]

    def run(self, page, ctx):
        findings = []
        if "?" not in page.url:
            return findings
        seen = set()
        for name, _ in iter_param_mutations(page.url, ""):
            if name in seen:
                continue
            seen.add(name)
            if name.lower() not in _URL_PARAM_HINTS:
                continue
            resp = ctx.http.get(set_param(page.url, name, _CANARY))
            if resp is None:
                continue
            body = (resp.text or "").lower()
            # Signals the server tried to fetch the canary (and failed, since
            # it does not resolve): DNS/connection errors naming the canary.
            signals = [
                "dastester-ssrf-probe.invalid",
                "name or service not known",
                "could not resolve host",
                "connection refused",
                "failed to open stream",
                "getaddrinfo",
            ]
            if any(s in body for s in signals):
                findings.append(Finding(
                    title=f"Potential SSRF surface via parameter '{name}'",
                    severity=Severity.HIGH,
                    description=(
                        f"The '{name}' parameter appears to cause a server-side "
                        "fetch: supplying a canary URL produced a fetch error "
                        "naming that host in the response. The server may be "
                        "coerced into requesting attacker-chosen locations "
                        "(SSRF)."
                    ),
                    url=page.url,
                    owasp="A10",
                    stride=["I", "E"],
                    cwe="CWE-918",
                    confidence=Confidence.MEDIUM,
                    evidence="Server-side fetch error referencing the canary host.",
                    remediation=(
                        "Validate and allow-list outbound request targets; block "
                        "internal ranges and cloud metadata endpoints; require "
                        "the fetch to go through a vetted egress proxy. Confirm "
                        "blind cases with an out-of-band (OAST) listener."
                    ),
                    reference="https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
                    check_id=self.id,
                ))
        return findings
