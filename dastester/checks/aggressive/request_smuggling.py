"""AGGRESSIVE check: HTTP request smuggling (timing-based detection).

This check uses the well-established *timing* technique to detect whether
a front-end and back-end disagree on how request boundaries are
determined (CL.TE / TE.CL desync). It does NOT smuggle a second,
victim-affecting request: it only observes whether a crafted request
causes the attacker's *own* connection to stall, which is the
non-destructive detection signal.

Even so, malformed requests can upset fragile infrastructure, so this
check only runs under --aggressive with authorisation, once per origin,
with tight timeouts.

Reference: PortSwigger's request-smuggling research (timing method).
"""

import socket
import ssl
import time
from urllib.parse import urlparse

from ..base import BaseCheck, AGGRESSIVE
from ...models import Finding, Severity, Confidence


def _send_raw(host, port, use_tls, payload, timeout):
    """Send a raw HTTP/1.1 request and return seconds until response/stall."""
    start = time.monotonic()
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.sendall(payload)
        sock.settimeout(timeout)
        try:
            sock.recv(4096)
        except socket.timeout:
            pass
    finally:
        try:
            sock.close()
        except Exception:
            pass
    return time.monotonic() - start


class RequestSmugglingCheck(BaseCheck):
    id = "request-smuggling"
    name = "HTTP request smuggling (timing)"
    kind = AGGRESSIVE
    owasp = "A05"
    stride = ["T", "D"]

    _probed = set()

    def run(self, page, ctx):
        findings = []
        p = urlparse(page.url)
        host = p.hostname
        if not host:
            return findings
        use_tls = p.scheme == "https"
        port = p.port or (443 if use_tls else 80)
        key = (host, port)
        if key in self._probed:
            return findings
        self._probed.add(key)

        path = p.path or "/"
        timeout = min(ctx.config.timeout, 10)

        # A normal request for baseline timing.
        normal = (
            f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
            f"User-Agent: {ctx.config.user_agent}\r\nConnection: close\r\n\r\n"
        ).encode()

        # CL.TE timing probe: the body ("X") is incomplete per the chunked
        # terminator, so a back-end that uses Transfer-Encoding will wait for
        # more data and stall. A front-end honouring Content-Length forwards
        # it as-is. This only stalls the attacker's own socket.
        clte = (
            f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
            "Transfer-Encoding: chunked\r\nContent-Length: 4\r\n"
            "Connection: close\r\n\r\n1\r\nA\r\nX"
        ).encode()

        try:
            base_t = _send_raw(host, port, use_tls, normal, timeout)
            probe_t = _send_raw(host, port, use_tls, clte, timeout)
        except Exception:
            return findings

        # A large stall on the probe (relative to baseline and near timeout)
        # is the desync signal.
        if probe_t >= timeout * 0.8 and probe_t > base_t + 3:
            findings.append(Finding(
                title="Possible HTTP request smuggling (CL.TE timing desync)",
                severity=Severity.HIGH,
                description=(
                    f"A crafted chunked request to {host}:{port} caused the "
                    f"connection to stall (~{probe_t:.1f}s vs baseline "
                    f"{base_t:.1f}s). This timing differential is consistent "
                    "with front-end/back-end disagreement over request "
                    "boundaries (request smuggling)."
                ),
                url=page.url,
                owasp="A05",
                stride=["T", "D", "S"],
                cwe="CWE-444",
                confidence=Confidence.LOW,
                evidence=f"baseline={base_t:.2f}s, CL.TE probe={probe_t:.2f}s",
                remediation=(
                    "Ensure front-end and back-end agree on request parsing; "
                    "reject requests with both Content-Length and "
                    "Transfer-Encoding; prefer HTTP/2 end-to-end. Confirm "
                    "manually before treating as exploitable."
                ),
                reference="https://portswigger.net/web-security/request-smuggling",
                check_id=self.id,
            ))
        return findings
