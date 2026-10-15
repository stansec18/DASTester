"""Access control testing scaffold: IDOR / BOLA / BFLA.

Broken object- and function-level authorisation (IDOR/BOLA/BFLA) cannot
be reliably detected by a single-session scanner: it requires at least
two authenticated identities and knowledge of which objects/functions
each should and should not reach. This module provides the framework and,
when supplied with two sessions + a list of endpoints, performs a safe
differential test:

    For each endpoint reachable as user A, re-request it as user B. If
    user B receives the same object/response that is specific to user A,
    that is a strong IDOR/BOLA indicator.

Wiring: populate ``config.access_control`` with:
    {
      "session_b": {"headers": {...}, "cookies": {...}},
      "endpoints": ["https://app/api/orders/1001", ...],
      "owner_markers": {"https://app/api/orders/1001": "alice@example.com"}
    }

Until configured, this check emits a single informational finding
describing how to enable it. It never attempts to guess object IDs on its
own, which keeps it from generating unauthorised access attempts blindly.
"""

from ..base import BaseCheck, ACTIVE
from ...models import Finding, Severity, Confidence


class AccessControlCheck(BaseCheck):
    id = "access-control"
    name = "Access control (IDOR/BOLA/BFLA) differential"
    kind = ACTIVE
    owasp = "A01"
    stride = ["E", "I"]

    _emitted_info = False
    _done = False

    def run(self, page, ctx):
        cfg = getattr(ctx.config, "access_control", None)

        # Not configured: explain how to use it, once per scan.
        if not cfg:
            if AccessControlCheck._emitted_info:
                return []
            AccessControlCheck._emitted_info = True
            return [Finding(
                title="Access control testing (IDOR/BOLA/BFLA) not configured",
                severity=Severity.INFO,
                description=(
                    "Object- and function-level authorisation testing requires "
                    "two authenticated identities and a list of endpoints. "
                    "Provide them via config.access_control to enable a safe "
                    "cross-account differential test. This single-session scan "
                    "cannot assess IDOR/BOLA/BFLA on its own."
                ),
                url=page.url,
                owasp="A01",
                stride=["E"],
                cwe="CWE-639",
                confidence=Confidence.HIGH,
                evidence="No second session / endpoint list supplied.",
                remediation=(
                    "Enforce server-side authorisation checks on every object "
                    "and function reference; never rely on client-supplied IDs."
                ),
                reference="https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
                check_id=self.id,
            )]

        # Configured: run the differential test once.
        if AccessControlCheck._done:
            return []
        AccessControlCheck._done = True

        findings = []
        session_b = cfg.get("session_b", {})
        endpoints = cfg.get("endpoints", [])
        owner_markers = cfg.get("owner_markers", {})
        headers_b = session_b.get("headers", {})
        cookies_b = session_b.get("cookies", {})

        for ep in endpoints:
            if not ctx.config.in_scope(ep):
                continue
            resp_b = ctx.http.get(ep, headers=headers_b, cookies=cookies_b)
            if resp_b is None:
                continue
            marker = owner_markers.get(ep)
            leaked = (
                resp_b.status == 200
                and marker
                and marker in (resp_b.text or "")
            )
            if leaked:
                findings.append(Finding(
                    title="Broken object-level authorisation (IDOR/BOLA)",
                    severity=Severity.HIGH,
                    description=(
                        f"User B was able to retrieve {ep}, which contains data "
                        f"belonging to another user (marker '{marker}' present). "
                        "Object-level authorisation is not enforced."
                    ),
                    url=ep,
                    owasp="A01",
                    stride=["E", "I"],
                    cwe="CWE-639",
                    confidence=Confidence.MEDIUM,
                    evidence=f"User B GET {ep} -> 200 containing owner marker.",
                    remediation=(
                        "Enforce per-object ownership checks server-side on every "
                        "request; do not trust client-supplied identifiers."
                    ),
                    reference="https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
                    check_id=self.id,
                ))
        return findings
