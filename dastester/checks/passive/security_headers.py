"""Passive check: presence and quality of HTTP security headers."""

from ..base import BaseCheck, PASSIVE
from ...models import Finding, Severity, Confidence

_EXPECTED = {
    "strict-transport-security": {
        "title": "Missing Strict-Transport-Security (HSTS) header",
        "severity": Severity.MEDIUM,
        "owasp": "A05",
        "stride": ["T", "I"],
        "cwe": "CWE-319",
        "remediation": (
            "Add 'Strict-Transport-Security: max-age=31536000; "
            "includeSubDomains' on all HTTPS responses to force browsers to "
            "use TLS."
        ),
        "https_only": True,
    },
    "content-security-policy": {
        "title": "Missing Content-Security-Policy header",
        "severity": Severity.MEDIUM,
        "owasp": "A05",
        "stride": ["T", "I"],
        "cwe": "CWE-693",
        "remediation": (
            "Define a Content-Security-Policy that restricts script, style, "
            "and object sources to trusted origins to reduce XSS impact."
        ),
    },
    "x-content-type-options": {
        "title": "Missing X-Content-Type-Options header",
        "severity": Severity.LOW,
        "owasp": "A05",
        "stride": ["T"],
        "cwe": "CWE-693",
        "remediation": "Set 'X-Content-Type-Options: nosniff'.",
    },
    "x-frame-options": {
        "title": "Missing framing protection (X-Frame-Options / CSP frame-ancestors)",
        "severity": Severity.LOW,
        "owasp": "A05",
        "stride": ["T"],
        "cwe": "CWE-1021",
        "remediation": (
            "Set 'X-Frame-Options: DENY' or a CSP 'frame-ancestors' directive "
            "to prevent clickjacking."
        ),
    },
    "referrer-policy": {
        "title": "Missing Referrer-Policy header",
        "severity": Severity.INFO,
        "owasp": "A05",
        "stride": ["I"],
        "cwe": "CWE-200",
        "remediation": "Set a restrictive 'Referrer-Policy' such as 'no-referrer'.",
    },
}


class SecurityHeadersCheck(BaseCheck):
    id = "security-headers"
    name = "HTTP security headers"
    kind = PASSIVE
    owasp = "A05"
    stride = ["T", "I"]

    def run(self, page, ctx):
        findings = []
        headers = {k.lower(): v for k, v in page.headers.items()}
        is_https = page.url.lower().startswith("https://")
        has_csp = "content-security-policy" in headers
        for key, meta in _EXPECTED.items():
            if meta.get("https_only") and not is_https:
                continue
            if key == "x-frame-options":
                # Satisfied by CSP frame-ancestors too.
                if "x-frame-options" in headers:
                    continue
                if has_csp and "frame-ancestors" in headers.get(
                    "content-security-policy", ""
                ):
                    continue
            elif key in headers:
                continue
            findings.append(Finding(
                title=meta["title"],
                severity=meta["severity"],
                description=(
                    f"The response for {page.url} does not set the "
                    f"'{key}' header (or an equivalent control)."
                ),
                url=page.url,
                owasp=meta["owasp"],
                stride=meta["stride"],
                cwe=meta.get("cwe"),
                confidence=Confidence.HIGH,
                evidence=f"Header '{key}' not present in response.",
                remediation=meta["remediation"],
                reference="https://owasp.org/www-project-secure-headers/",
                check_id=self.id,
            ))
        return findings
