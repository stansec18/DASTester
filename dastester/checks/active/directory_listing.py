"""Active check: directory listing and deep sensitive file exposure."""

from urllib.parse import urljoin
from ..base import BaseCheck, ACTIVE
from ...models import Finding, Severity, Confidence

_SENSITIVE_FILES = [
    (".env", "Exposed Environment Configuration File (.env)", Severity.CRITICAL, "CWE-540", "Yes"),
    ("config/database.yml", "Exposed Database Configuration File", Severity.CRITICAL, "CWE-540", "Yes"),
    ("wp-config.php.bak", "Exposed WordPress Configuration Backup", Severity.CRITICAL, "CWE-530", "No"),
    (".git/HEAD", "Exposed Version Control Metadata (.git)", Severity.HIGH, "CWE-540", "No"),
    ("backup.zip", "Publicly Accessible Backup Archive", Severity.CRITICAL, "CWE-530", "No"),
    ("swagger.json", "Exposed API Documentation / Schema", Severity.LOW, "CWE-200", "No"),
]

_SECRET_PATTERNS = [
    "DB_PASSWORD", "DATABASE_URL", "SMTP_PASSWORD", "AWS_SECRET", 
    "API_KEY", "PRIVATE_KEY", "SECRET_KEY", "bearer", "password="
]


class DirectoryListingCheck(BaseCheck):
    id = "exposure-files"
    name = "Directory listing and sensitive file exposure"
    kind = ACTIVE
    owasp = "A05:2021"
    stride = ["I"]

    _probed_roots = set()

    def run(self, page, ctx):
        findings = []
        body = page.body or ""

        # Check for directory auto-indexing
        if "Index of /" in body or "<title>Directory listing for" in body:
            findings.append(Finding(
                title="Directory Listing Enabled on Server",
                severity=Severity.MEDIUM,
                description="The server automatically lists directory contents, allowing attackers to discover unlinked backup, config, or source files.",
                url=page.url,
                owasp="A05:2021",
                stride=["I"],
                cwe="CWE-548",
                attack_vector="Network",
                exploitability="Easy",
                auth_required="No",
                confidence=Confidence.HIGH,
                evidence="Directory index signature matched in response body.",
                remediation="Disable automatic directory indexing in your web server configuration (e.g., 'Options -Indexes' in Apache or 'autoindex off' in Nginx).",
                reference="https://owasp.org/www-project-web-security-testing-guide/",
                check_id=self.id,
            ))

        # Probe sensitive files across the domain root
        from urllib.parse import urlparse
        p = urlparse(page.url)
        root = f"{p.scheme}://{p.netloc}/"
        if root in self._probed_roots:
            return findings
        self._probed_roots.add(root)

        for path, title, sev, cwe, auth in _SENSITIVE_FILES:
            url = urljoin(root, path)
            resp = ctx.http.get(url)
            if resp is None or resp.status != 200 or not resp.text:
                continue

            # Skip catch-all custom 404 pages returning 200 OK
            if len(resp.text.strip()) < 10 or "<html" in resp.text.lower() and "not found" in resp.text.lower():
                continue

            evidence_text = f"HTTP 200 OK returned for /{path} ({len(resp.text)} bytes)"
            actual_severity = sev

            # Deep content inspection for secrets
            if any(pattern in resp.text for pattern in _SECRET_PATTERNS):
                actual_severity = Severity.CRITICAL
                evidence_text = f"Confirmed sensitive secrets (database passwords/API keys) exposed in /{path}"

            findings.append(Finding(
                title=title,
                severity=actual_severity,
                description=f"A sensitive system file ({path}) was found publicly accessible without authentication. This file contains internal configuration data or credentials.",
                url=url,
                owasp="A05:2021",
                stride=["I"],
                cwe=cwe,
                attack_vector="Network",
                exploitability="Easy",
                auth_required=auth,
                confidence=Confidence.HIGH,
                evidence=evidence_text,
                remediation="Remove sensitive files from your public web root immediately, restrict file permissions, and rotate any exposed credentials.",
                reference="https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                check_id=self.id,
            ))
        return findings
