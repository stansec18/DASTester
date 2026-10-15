"""Passive check: Cross-Site Request Forgery protection on forms.

Analyses forms already collected during the crawl. A state-changing
(POST) form that contains no recognisable anti-CSRF token and whose
session cookies lack SameSite protection is flagged. This reads the
crawl output only — it sends no requests.
"""

import re

from ..base import BaseCheck, PASSIVE
from ...models import Finding, Severity, Confidence

_TOKEN_HINTS = re.compile(
    r"csrf|xsrf|authenticity_token|__requestverificationtoken|nonce|_token",
    re.I,
)


class CsrfCheck(BaseCheck):
    id = "csrf-forms"
    name = "Cross-Site Request Forgery (CSRF) protection"
    kind = PASSIVE
    owasp = "A01"
    stride = ["S", "T"]

    def run(self, page, ctx):
        findings = []
        # Does the site rely on SameSite cookies for CSRF defence?
        samesite = False
        for k, v in page.headers.items():
            if k.lower() == "set-cookie" and "samesite" in v.lower():
                if "samesite=none" not in v.lower():
                    samesite = True

        for form in page.forms:
            if form.get("method", "get").lower() != "post":
                continue
            names = " ".join(i.get("name", "") for i in form.get("inputs", []))
            types = " ".join(i.get("type", "") for i in form.get("inputs", []))
            has_token = bool(_TOKEN_HINTS.search(names)) or "hidden" in types and \
                bool(_TOKEN_HINTS.search(names))
            if has_token:
                continue
            # No token found. If SameSite protects the session, lower severity.
            sev = Severity.LOW if samesite else Severity.MEDIUM
            findings.append(Finding(
                title="State-changing form without anti-CSRF token",
                severity=sev,
                description=(
                    f"A POST form on {page.url} (action: {form.get('action')}) "
                    "contains no recognisable anti-CSRF token. If the session "
                    "relies on cookies, it may be vulnerable to CSRF."
                ),
                url=page.url,
                owasp="A01",
                stride=["S", "T"],
                cwe="CWE-352",
                confidence=Confidence.LOW,
                evidence=f"Form inputs: {names[:120] or '(none named)'}",
                remediation=(
                    "Add a per-session, per-request anti-CSRF token to all "
                    "state-changing forms and set SameSite=Lax/Strict on session "
                    "cookies."
                ),
                reference="https://owasp.org/www-community/attacks/csrf",
                check_id=self.id,
            ))
        return findings
