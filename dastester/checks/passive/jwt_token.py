"""Passive check: JSON Web Token (JWT) weaknesses.

Finds JWTs in Set-Cookie headers, Authorization headers echoed back, or
the response body, decodes the header/payload (no signature verification
needed to assess these), and flags:
  - alg: none (unsigned token accepted/issued)
  - weak HMAC secret (tested against a tiny built-in list of notoriously
    weak secrets, offline, no requests)
  - missing expiry (exp) claim

Only the token's own structure is examined; DASTester does not forge or
replay tokens.
"""

import base64
import hashlib
import hmac
import json
import re

from ..base import BaseCheck, PASSIVE
from ...models import Finding, Severity, Confidence

_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")
# A short list of infamously weak signing secrets, checked offline only.
_WEAK_SECRETS = ["secret", "password", "changeme", "jwt", "test", "admin",
                 "123456", "key", "your-256-bit-secret"]


def _b64url_decode(seg):
    seg += "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg)


class JwtCheck(BaseCheck):
    id = "jwt-token"
    name = "JWT / token weaknesses"
    kind = PASSIVE
    owasp = "A07"
    stride = ["S", "E"]

    _seen = set()

    def run(self, page, ctx):
        findings = []
        haystack = " ".join(str(v) for v in page.headers.values())
        haystack += " " + (page.body or "")[:20000]
        for token in set(_JWT_RE.findall(haystack)):
            if token[:40] in self._seen:
                continue
            self._seen.add(token[:40])
            parts = token.split(".")
            if len(parts) < 2:
                continue
            try:
                header = json.loads(_b64url_decode(parts[0]))
                payload = json.loads(_b64url_decode(parts[1]))
            except Exception:
                continue

            alg = str(header.get("alg", "")).lower()
            if alg in ("none", ""):
                findings.append(self._f(
                    page, "JWT uses 'alg: none' (unsigned)", Severity.HIGH,
                    "A JWT with algorithm 'none' is unsigned; if the server "
                    "accepts it, tokens can be forged arbitrarily.",
                    "CWE-347", f"alg={header.get('alg')}", Confidence.MEDIUM,
                    "Reject 'none'; require a strong signing algorithm (RS256/"
                    "ES256) and validate it server-side."))

            if "exp" not in payload:
                findings.append(self._f(
                    page, "JWT without expiry (exp) claim", Severity.MEDIUM,
                    "The token has no 'exp' claim, so it never expires and "
                    "remains valid indefinitely if leaked.",
                    "CWE-613", "no 'exp' claim", Confidence.MEDIUM,
                    "Issue short-lived tokens with an 'exp' claim and rotate them."))

            # Offline weak-secret test for HMAC tokens only.
            if alg.startswith("hs") and len(parts) == 3:
                signing_input = f"{parts[0]}.{parts[1]}".encode()
                digestmod = {"hs256": hashlib.sha256, "hs384": hashlib.sha384,
                             "hs512": hashlib.sha512}.get(alg, hashlib.sha256)
                for secret in _WEAK_SECRETS:
                    sig = base64.urlsafe_b64encode(
                        hmac.new(secret.encode(), signing_input, digestmod).digest()
                    ).rstrip(b"=").decode()
                    if hmac.compare_digest(sig, parts[2]):
                        findings.append(self._f(
                            page, "JWT signed with a weak/guessable secret",
                            Severity.CRITICAL,
                            "The HMAC signature was reproduced offline using a "
                            f"well-known weak secret ('{secret}'). Anyone who "
                            "guesses the secret can forge valid tokens.",
                            "CWE-326", f"secret matched: '{secret}'",
                            Confidence.HIGH,
                            "Use a long, random, high-entropy signing secret "
                            "stored securely; rotate it."))
                        break
        return findings

    def _f(self, page, title, sev, desc, cwe, ev, conf, rem):
        return Finding(
            title=title, severity=sev, description=desc, url=page.url,
            owasp="A07", stride=["S", "E"], cwe=cwe, confidence=conf,
            evidence=ev, remediation=rem,
            reference="https://owasp.org/www-project-web-security-testing-guide/",
            check_id=self.id,
        )
