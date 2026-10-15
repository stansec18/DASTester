"""Active check: blind SQL injection surface (boolean and time based).

Detection approach, baseline-aware and non-destructive:

  Boolean: compare the response to a value appended with a condition that
  is always TRUE versus one that is always FALSE. A consistent, large
  difference between the two (while the TRUE case resembles the baseline)
  suggests the input influences a SQL boolean context.

  Time: append a short, bounded delay expression and measure whether the
  response time increases by roughly the requested delay relative to the
  baseline. The delay is kept small (a few seconds) to avoid any impact.

These probes only *read* the application's observable behaviour; they do
not read, modify, or extract data.
"""

import time

from ..base import BaseCheck, ACTIVE
from ...models import Finding, Severity, Confidence
from ._util import iter_param_mutations, set_param

# Bounded, inert comparison payloads (no stacked queries, no data access).
_TRUE = "' AND '1'='1"
_FALSE = "' AND '1'='2"
# A small, bounded delay. Engine-agnostic variants, delay kept low.
_DELAY_SECONDS = 4
_DELAY_PAYLOADS = [
    f"'||pg_sleep({_DELAY_SECONDS})||'",      # PostgreSQL
    f"' AND SLEEP({_DELAY_SECONDS})-- -",     # MySQL
]


def _similar(a: str, b: str) -> float:
    if not a and not b:
        return 1.0
    la, lb = len(a), len(b)
    return 1.0 - abs(la - lb) / max(la, lb, 1)


class SqlBlindCheck(BaseCheck):
    id = "sql-blind"
    name = "Blind SQL injection surface (boolean/time)"
    kind = ACTIVE
    owasp = "A03"
    stride = ["T", "I", "E"]

    def run(self, page, ctx):
        findings = []
        if "?" not in page.url:
            return findings
        baseline = page.body or ""
        seen = set()
        for name, _ in iter_param_mutations(page.url, ""):
            if name in seen:
                continue
            seen.add(name)

            # --- Boolean-based ---
            t = ctx.http.get(set_param(page.url, name, "x" + _TRUE))
            f = ctx.http.get(set_param(page.url, name, "x" + _FALSE))
            if t and f and t.text and f.text:
                true_vs_base = _similar(t.text, baseline)
                true_vs_false = _similar(t.text, f.text)
                # TRUE resembles baseline, FALSE differs clearly.
                if true_vs_base > 0.95 and true_vs_false < 0.85:
                    findings.append(self._f(
                        page, name, "Boolean-based blind SQL injection surface",
                        Severity.HIGH, Confidence.LOW,
                        "Responses differ consistently between an always-true "
                        "and always-false SQL condition injected into the "
                        f"'{name}' parameter, indicating a blind SQLi surface.",
                        f"true~baseline={true_vs_base:.2f}, true~false={true_vs_false:.2f}"))
                    continue

            # --- Time-based (only if boolean was inconclusive) ---
            # Baseline timing.
            base_resp = ctx.http.get(set_param(page.url, name, "x"))
            base_time = base_resp.elapsed if base_resp else 0.0
            for payload in _DELAY_PAYLOADS:
                start = time.monotonic()
                r = ctx.http.get(set_param(page.url, name, "x" + payload))
                elapsed = time.monotonic() - start
                if r is not None and elapsed >= _DELAY_SECONDS * 0.8 and \
                        elapsed > base_time + _DELAY_SECONDS * 0.6:
                    findings.append(self._f(
                        page, name, "Time-based blind SQL injection surface",
                        Severity.HIGH, Confidence.LOW,
                        "Injecting a bounded delay expression into the "
                        f"'{name}' parameter delayed the response by ~"
                        f"{elapsed:.1f}s, indicating the input reaches a SQL "
                        "engine (time-based blind SQLi).",
                        f"baseline={base_time:.2f}s, delayed={elapsed:.2f}s"))
                    break
        return findings

    def _f(self, page, name, title, sev, conf, desc, ev):
        return Finding(
            title=f"{title} (parameter '{name}')", severity=sev,
            description=desc, url=page.url, owasp="A03",
            stride=["T", "I", "E"], cwe="CWE-89", confidence=conf,
            evidence=ev,
            remediation=(
                "Use parameterised queries / prepared statements; validate and "
                "allow-list input. Never concatenate input into SQL."
            ),
            reference="https://owasp.org/www-community/attacks/Blind_SQL_Injection",
            check_id=self.id,
        )
