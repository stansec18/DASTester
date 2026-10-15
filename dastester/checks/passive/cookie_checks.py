"""Passive check: session cookie security attributes."""

import re

from ..base import BaseCheck, PASSIVE
from ...models import Finding, Severity, Confidence

_SESSION_HINTS = ("sess", "sid", "auth", "token", "jwt", "login")


class CookieCheck(BaseCheck):
    id = "cookie-flags"
    name = "Cookie security attributes"
    kind = PASSIVE
    owasp = "A07"
    stride = ["S", "I"]

    def run(self, page, ctx):
        findings = []
        set_cookies = []
        for k, v in page.headers.items():
            if k.lower() == "set-cookie":
                set_cookies.append(v)
        # requests folds multiple Set-Cookie into one comma-joined string.
        raw = "\n".join(set_cookies)
        for line in re.split(r",(?=[^;]+?=)|\n", raw):
            line = line.strip()
            if not line or "=" not in line:
                continue
            name = line.split("=", 1)[0].strip().lower()
            low = line.lower()
            is_session = any(h in name for h in _SESSION_HINTS)
            missing = []
            if "secure" not in low:
                missing.append("Secure")
            if "httponly" not in low:
                missing.append("HttpOnly")
            if "samesite" not in low:
                missing.append("SameSite")
            if not missing:
                continue
            sev = Severity.MEDIUM if is_session else Severity.LOW
            findings.append(Finding(
                title=f"Cookie '{name}' missing {', '.join(missing)} attribute(s)",
                severity=sev,
                description=(
                    f"The cookie '{name}' set by {page.url} is missing the "
                    f"{', '.join(missing)} attribute(s), weakening session "
                    "protection."
                ),
                url=page.url,
                owasp="A07",
                stride=["S", "I"],
                cwe="CWE-614",
                confidence=Confidence.HIGH,
                evidence=f"Set-Cookie: {line[:120]}",
                remediation=(
                    "Set Secure, HttpOnly, and an appropriate SameSite value on "
                    "session cookies."
                ),
                reference="https://owasp.org/www-community/controls/SecureCookieAttribute",
                check_id=self.id,
            ))
        return findings
