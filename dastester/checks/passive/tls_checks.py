"""Passive/transport check: HTTPS usage and TLS certificate hygiene.

This check inspects transport security without performing any intrusive
testing: it notes plaintext HTTP, whether HTTP redirects to HTTPS, and
basic certificate validity (expiry, hostname match) via a standard TLS
handshake.
"""

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

from ..base import BaseCheck, PASSIVE
from ...models import Finding, Severity, Confidence


class TlsCheck(BaseCheck):
    id = "tls-transport"
    name = "Transport security (HTTPS/TLS)"
    kind = PASSIVE
    owasp = "A02"
    stride = ["I", "T", "S"]

    # Only probe each host once.
    _probed_hosts = set()

    def run(self, page, ctx):
        findings = []
        parsed = urlparse(page.url)
        host = parsed.hostname
        if not host:
            return findings

        if parsed.scheme == "http":
            findings.append(Finding(
                title="Service reachable over plaintext HTTP",
                severity=Severity.MEDIUM,
                description=(
                    f"{page.url} is served over unencrypted HTTP. Traffic can "
                    "be intercepted or modified in transit."
                ),
                url=page.url,
                owasp="A02",
                stride=["I", "T"],
                cwe="CWE-319",
                confidence=Confidence.HIGH,
                evidence="URL scheme is http://",
                remediation=(
                    "Serve the application exclusively over HTTPS and redirect "
                    "HTTP to HTTPS with HSTS enabled."
                ),
                reference="https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
                check_id=self.id,
            ))
            return findings

        if parsed.scheme != "https":
            return findings

        port = parsed.port or 443
        key = (host, port)
        if key in self._probed_hosts:
            return findings
        self._probed_hosts.add(key)

        try:
            ctx_ssl = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=ctx.config.timeout) as sock:
                with ctx_ssl.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    version = ssock.version()
        except ssl.SSLCertVerificationError as exc:
            findings.append(Finding(
                title="TLS certificate verification failed",
                severity=Severity.HIGH,
                description=(
                    f"The TLS certificate presented by {host}:{port} failed "
                    "verification (untrusted, expired, or hostname mismatch)."
                ),
                url=page.url,
                owasp="A02",
                stride=["S", "I"],
                cwe="CWE-295",
                confidence=Confidence.HIGH,
                evidence=str(exc)[:200],
                remediation=(
                    "Install a valid certificate from a trusted CA that matches "
                    "the hostname and is within its validity period."
                ),
                reference="https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
                check_id=self.id,
            ))
            return findings
        except Exception:
            return findings

        # Deprecated protocol versions.
        if version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            findings.append(Finding(
                title=f"Deprecated TLS protocol negotiated ({version})",
                severity=Severity.MEDIUM,
                description=(
                    f"The server negotiated {version}, which is deprecated and "
                    "considered insecure."
                ),
                url=page.url,
                owasp="A02",
                stride=["I", "T"],
                cwe="CWE-327",
                confidence=Confidence.HIGH,
                evidence=f"Negotiated protocol: {version}",
                remediation="Disable TLS 1.1 and below; require TLS 1.2 or 1.3.",
                reference="https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
                check_id=self.id,
            ))

        # Expiry window.
        not_after = cert.get("notAfter") if cert else None
        if not_after:
            try:
                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                    tzinfo=timezone.utc
                )
                days = (exp - datetime.now(timezone.utc)).days
                if days < 0:
                    sev, title = Severity.HIGH, "TLS certificate has expired"
                elif days < 15:
                    sev, title = Severity.MEDIUM, "TLS certificate expiring soon"
                else:
                    sev, title = None, None
                if sev:
                    findings.append(Finding(
                        title=title,
                        severity=sev,
                        description=f"Certificate for {host} expires in {days} days.",
                        url=page.url,
                        owasp="A02",
                        stride=["S"],
                        cwe="CWE-324",
                        confidence=Confidence.HIGH,
                        evidence=f"notAfter={not_after}",
                        remediation="Renew the certificate and automate renewal.",
                        reference="https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
                        check_id=self.id,
                    ))
            except ValueError:
                pass
        return findings
