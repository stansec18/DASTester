"""Active check: unsanitised reflection of input (XSS surface).

Detection approach: inject a unique, inert marker token into each query
parameter and observe whether it is reflected into the response in a
context where it is not HTML-encoded. This indicates the application
reflects input without output encoding -- the precondition for reflected
cross-site scripting. DASTester reports the weakness; it does not attempt
to execute script or deliver a working exploit.
"""

import re
import secrets

from ..base import BaseCheck, ACTIVE
from ...models import Finding, Severity, Confidence
from ._util import iter_param_mutations


class ReflectedInputCheck(BaseCheck):
    id = "reflected-input"
    name = "Reflected unsanitised input (XSS surface)"
    kind = ACTIVE
    owasp = "A03"
    stride = ["T", "S"]

    def run(self, page, ctx):
        findings = []
        if "?" not in page.url:
            return findings
        seen_params = set()
        for name, _mutated in iter_param_mutations(page.url, ""):
            if name in seen_params:
                continue
            seen_params.add(name)
            token = "dastester" + secrets.token_hex(4)
            # A marker wrapped in angle brackets: if it comes back verbatim
            # (not entity-encoded), output encoding is missing.
            probe = f"<{token}>"
            target = next(
                (m for n, m in iter_param_mutations(page.url, probe) if n == name),
                None,
            )
            if not target:
                continue
            resp = ctx.http.get(target)
            if resp is None or not resp.text:
                continue
            raw_reflected = f"<{token}>" in resp.text
            encoded_reflected = (
                f"&lt;{token}&gt;" in resp.text or f"&#60;{token}" in resp.text
            )
            if raw_reflected and not encoded_reflected:
                findings.append(Finding(
                    title=f"Input reflected without output encoding (parameter '{name}')",
                    severity=Severity.HIGH,
                    description=(
                        f"The '{name}' parameter is reflected into the response "
                        "without HTML output encoding. This is the precondition "
                        "for reflected cross-site scripting (XSS)."
                    ),
                    url=page.url,
                    owasp="A03",
                    stride=["T", "S"],
                    cwe="CWE-79",
                    confidence=Confidence.MEDIUM,
                    evidence=(
                        f"Inert marker '<{token}>' returned un-encoded in the "
                        "response body."
                    ),
                    remediation=(
                        "Apply context-aware output encoding to all reflected "
                        "user input and adopt a strict Content-Security-Policy."
                    ),
                    reference="https://owasp.org/www-community/attacks/xss/",
                    check_id=self.id,
                ))
        return findings
