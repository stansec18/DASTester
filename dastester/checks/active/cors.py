"""Active check: CORS misconfiguration.

Sends a request with a crafted (off-scope) Origin header once per origin
and inspects the CORS response headers. Flags:
  - Reflected arbitrary Origin together with credentials allowed
    (the most dangerous CORS misconfiguration)
  - Access-Control-Allow-Origin: * together with credentials
  - Trust of a 'null' origin

Only a GET with a benign Origin header is sent; nothing is modified.
"""

from urllib.parse import urlparse

from ..base import BaseCheck, ACTIVE
from ...models import Finding, Severity, Confidence

_EVIL_ORIGIN = "https://dastester-cors-probe.invalid"


class CorsCheck(BaseCheck):
    id = "cors-misconfig"
    name = "CORS misconfiguration"
    kind = ACTIVE
    owasp = "A05"
    stride = ["S", "I"]

    # Per-origin probe budget and a flag set once a finding is reported, so
    # we examine a few representative pages (CORS often differs by endpoint)
    # without probing every crawled page.
    _probe_count = {}
    _found = set()
    _MAX_PER_ORIGIN = 6

    def run(self, page, ctx):
        findings = []
        p = urlparse(page.url)
        root = f"{p.scheme}://{p.netloc}/"
        if root in self._found:
            return findings
        n = self._probe_count.get(root, 0)
        if n >= self._MAX_PER_ORIGIN:
            return findings
        self._probe_count[root] = n + 1

        resp = ctx.http.get(page.url, headers={"Origin": _EVIL_ORIGIN})
        if resp is None:
            return findings
        h = {k.lower(): v for k, v in resp.headers.items()}
        acao = h.get("access-control-allow-origin", "")
        acac = h.get("access-control-allow-credentials", "").lower() == "true"

        if acao == _EVIL_ORIGIN and acac:
            findings.append(self._f(
                page, "CORS reflects arbitrary Origin with credentials",
                Severity.HIGH,
                "The server reflects any supplied Origin in "
                "Access-Control-Allow-Origin and allows credentials, letting a "
                "malicious site read authenticated responses.",
                f"ACAO reflected '{_EVIL_ORIGIN}', ACAC=true", Confidence.HIGH))
        elif acao == "*" and acac:
            findings.append(self._f(
                page, "CORS allows any origin with credentials",
                Severity.MEDIUM,
                "Access-Control-Allow-Origin is '*' while credentials are "
                "allowed (a configuration most browsers reject, but a risk).",
                "ACAO=*, ACAC=true", Confidence.MEDIUM))
        elif acao == _EVIL_ORIGIN:
            findings.append(self._f(
                page, "CORS reflects arbitrary Origin",
                Severity.LOW,
                "The server reflects the supplied Origin without an allow-list. "
                "Combined with credentials this would be exploitable.",
                f"ACAO reflected '{_EVIL_ORIGIN}'", Confidence.MEDIUM))

        # 'null' origin trust.
        resp2 = ctx.http.get(page.url, headers={"Origin": "null"})
        if resp2:
            h2 = {k.lower(): v for k, v in resp2.headers.items()}
            if h2.get("access-control-allow-origin", "") == "null":
                findings.append(self._f(
                    page, "CORS trusts the 'null' origin",
                    Severity.MEDIUM,
                    "The server allows the 'null' origin, which can be forged by "
                    "sandboxed iframes and some local contexts.",
                    "ACAO=null", Confidence.MEDIUM))

        if findings:
            self._found.add(root)  # stop probing this origin once confirmed
        return findings

    def _f(self, page, title, sev, desc, ev, conf):
        return Finding(
            title=title, severity=sev, description=desc, url=page.url,
            owasp="A05", stride=["S", "I"], cwe="CWE-942", confidence=conf,
            evidence=ev,
            remediation=(
                "Validate Origin against a strict allow-list; never reflect "
                "arbitrary origins; avoid combining wildcard/reflected origins "
                "with Allow-Credentials."
            ),
            reference="https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
            check_id=self.id,
        )
