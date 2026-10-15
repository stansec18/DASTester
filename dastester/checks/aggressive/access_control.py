"""Active check: object-level access control (IDOR/BOLA) verification."""

from ..base import BaseCheck, ACTIVE
from ...models import Finding, Severity, Confidence


class AccessControlCheck(BaseCheck):
    id = "access-control"
    name = "Access Control & Authorization Check (IDOR)"
    kind = ACTIVE
    owasp = "A01:2021"
    stride = ["E", "I"]

    _emitted_info = False
    _done = False

    def run(self, page, ctx):
        cfg = getattr(ctx.config, "access_control", None)

        if not cfg:
            if AccessControlCheck._emitted_info:
                return []
            AccessControlCheck._emitted_info = True
            return [Finding(
                title="Authorization Testing Not Fully Configured",
                severity=Severity.INFO,
                description=(
                    "Automated scanners cannot safely guess user account objects without two active sessions. "
                    "To test for IDOR/BOLA, supply a second user's session headers and target endpoints in your configuration."
                ),
                url=page.url,
                owasp="A01:2021",
                stride=["E"],
                cwe="CWE-639",
                attack_vector="Network",
                exploitability="Moderate",
                auth_required="Yes",
                confidence=Confidence.HIGH,
                evidence="Single-session scan context detected.",
                remediation="Configure multi-session testing to validate that users cannot access records belonging to others.",
                reference="https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
                check_id=self.id,
            )]

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
            if resp_b.status == 200 and marker and marker in (resp_b.text or ""):
                findings.append(Finding(
                    title="Unauthorized Access to Private User Records (IDOR / BOLA)",
                    severity=Severity.HIGH,
                    description=(
                        "A secondary user account was able to view private account records or data "
                        "belonging to another user simply by modifying or requesting the resource URL directly, "
                        "bypassing server-side authorization checks."
                    ),
                    url=ep,
                    owasp="A01:2021",
                    stride=["E", "I"],
                    cwe="CWE-639",
                    attack_vector="Network",
                    exploitability="Easy",
                    auth_required="Yes",
                    confidence=Confidence.HIGH,
                    evidence=f"Second user successfully retrieved protected endpoint {ep} containing user data markers.",
                    remediation=(
                        "Enforce strict ownership and role verification checks on the server side "
                        "for every requested record ID. Never trust client-supplied identifiers."
                    ),
                    reference="https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
                    check_id=self.id,
                ))
        return findings
