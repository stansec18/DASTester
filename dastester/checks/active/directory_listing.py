"""Active check: directory listing and common sensitive files.

Detection approach: probe a small, fixed list of well-known paths that
should not be publicly readable (version-control metadata, backup/config
files) and detect auto-indexing. Only GET requests are made, strictly
within scope. This surfaces misconfiguration without any destructive
action.
"""

from urllib.parse import urljoin

from ..base import BaseCheck, ACTIVE
from ...models import Finding, Severity, Confidence

# Conservative, well-known paths. Kept small to stay polite.
_SENSITIVE_PATHS = [
    (".git/HEAD", "Exposed Git metadata (.git)"),
    (".env", "Exposed environment file (.env)"),
    ("backup.zip", "Publicly accessible backup archive"),
    ("web.config", "Exposed server configuration file"),
    (".DS_Store", "Exposed .DS_Store directory index"),
]

_LISTING_MARKERS = ("Index of /", "<title>Directory listing for")


class DirectoryListingCheck(BaseCheck):
    id = "exposure-files"
    name = "Directory listing and sensitive file exposure"
    kind = ACTIVE
    owasp = "A05"
    stride = ["I"]

    _probed_roots = set()

    def run(self, page, ctx):
        findings = []
        body = page.body or ""

        # Auto-index on the page itself.
        for marker in _LISTING_MARKERS:
            if marker in body:
                findings.append(Finding(
                    title="Directory listing enabled",
                    severity=Severity.MEDIUM,
                    description=(
                        f"{page.url} returns an auto-generated directory listing, "
                        "exposing file names and structure."
                    ),
                    url=page.url,
                    owasp="A05",
                    stride=["I"],
                    cwe="CWE-548",
                    confidence=Confidence.HIGH,
                    evidence=f"Marker found: {marker!r}",
                    remediation="Disable automatic directory indexing on the web server.",
                    reference="https://owasp.org/www-project-web-security-testing-guide/",
                    check_id=self.id,
                ))
                break

        # Probe sensitive paths once per host root.
        from urllib.parse import urlparse
        p = urlparse(page.url)
        root = f"{p.scheme}://{p.netloc}/"
        if root in self._probed_roots:
            return findings
        self._probed_roots.add(root)

        for path, title in _SENSITIVE_PATHS:
            url = urljoin(root, path)
            resp = ctx.http.get(url)
            if resp is None:
                continue
            if resp.status == 200 and resp.text and len(resp.text.strip()) > 0:
                # Avoid flagging a catch-all 200 that returns the homepage.
                if path == ".git/HEAD" and "ref:" not in resp.text:
                    continue
                findings.append(Finding(
                    title=title,
                    severity=Severity.MEDIUM,
                    description=(
                        f"The path /{path} is publicly accessible and returned "
                        "HTTP 200. Such files can leak source, secrets, or "
                        "configuration."
                    ),
                    url=url,
                    owasp="A05",
                    stride=["I"],
                    cwe="CWE-538",
                    confidence=Confidence.MEDIUM,
                    evidence=f"GET /{path} -> 200 ({len(resp.text)} bytes)",
                    remediation=(
                        "Remove the file from the web root or block access to it "
                        "at the server/CDN layer."
                    ),
                    reference="https://owasp.org/www-project-web-security-testing-guide/",
                    check_id=self.id,
                ))
        return findings
