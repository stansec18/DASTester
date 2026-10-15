"""AGGRESSIVE check: SSRF probing of internal / metadata targets.

Extends the safe SSRF surface check by pointing suspected URL-fetching
parameters at internal and cloud-metadata addresses, then looking for
signals that the server reached them (reflected metadata content,
distinctive status/latency differences).

This is gated behind --aggressive because directing a server at its own
internal network can have side effects. It is still read-only in intent:
it never writes data, and it only reads what the vulnerable server itself
returns.
"""

from ..base import BaseCheck, AGGRESSIVE
from ...models import Finding, Severity, Confidence
from ..active._util import iter_param_mutations, set_param

_URL_PARAM_HINTS = ("url", "uri", "link", "src", "source", "dest", "target",
                    "fetch", "load", "import", "callback", "feed", "proxy",
                    "image", "img", "file", "path", "domain", "host")

# Internal / metadata probe targets and fingerprints of a successful fetch.
_PROBES = [
    ("http://169.254.169.254/latest/meta-data/",
     ("ami-id", "instance-id", "iam/", "meta-data")),          # AWS IMDS
    ("http://metadata.google.internal/computeMetadata/v1/",
     ("computeMetadata", "project-id")),                        # GCP
    ("http://127.0.0.1:80/", ("<html", "server:")),            # loopback
]


class SsrfAggressiveCheck(BaseCheck):
    id = "ssrf-internal"
    name = "SSRF internal/metadata probing (aggressive)"
    kind = AGGRESSIVE
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
            for target, fingerprints in _PROBES:
                resp = ctx.http.get(set_param(page.url, name, target))
                if resp is None or not resp.text:
                    continue
                low = resp.text.lower()
                if any(fp.lower() in low for fp in fingerprints):
                    findings.append(Finding(
                        title=f"SSRF to internal target confirmed via '{name}'",
                        severity=Severity.CRITICAL,
                        description=(
                            f"Pointing '{name}' at {target} returned content "
                            "characteristic of that internal/metadata endpoint, "
                            "indicating the server can be coerced into reaching "
                            "internal resources (SSRF)."
                        ),
                        url=page.url,
                        owasp="A10",
                        stride=["I", "E"],
                        cwe="CWE-918",
                        confidence=Confidence.MEDIUM,
                        evidence=f"Response to {target} matched internal fingerprint.",
                        remediation=(
                            "Block requests to internal ranges and cloud metadata "
                            "(e.g. 169.254.169.254); enforce an egress allow-list; "
                            "require IMDSv2 / hop-limit on cloud instances."
                        ),
                        reference="https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
                        check_id=self.id,
                    ))
                    break
        return findings
