"""Active check: error-based SQL injection surface.

Detection approach: append a single inert syntax-breaking character to a
parameter and look for database error signatures in the response that
were NOT present in the baseline. A baseline-aware, error-signature-only
method keeps this non-destructive (no data is read, altered, or
extracted) while still surfacing parameters that pass input into a query
unsafely.
"""

import re

from ..base import BaseCheck, ACTIVE
from ...models import Finding, Severity, Confidence
from ._util import iter_param_mutations, set_param

# Signatures of database errors across common engines.
_DB_ERRORS = [
    r"you have an error in your sql syntax",
    r"warning:\s+mysqli?",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"pg_query\(\)",
    r"sqlstate\[",
    r"ORA-\d{5}",
    r"sqlite3?::",
    r"microsoft odbc .* driver",
    r"org\.postgresql\.util\.psqlexception",
]
_DB_RE = re.compile("|".join(_DB_ERRORS), re.I)


class SqlErrorCheck(BaseCheck):
    id = "sql-error"
    name = "Error-based SQL injection surface"
    kind = ACTIVE
    owasp = "A03"
    stride = ["T", "I", "E"]

    def run(self, page, ctx):
        findings = []
        if "?" not in page.url:
            return findings
        # Baseline: does the clean page already contain DB error text?
        base_has_error = bool(_DB_RE.search(page.body or ""))

        seen = set()
        for name, _ in iter_param_mutations(page.url, ""):
            if name in seen:
                continue
            seen.add(name)
            # A single quote is the canonical, inert syntax probe.
            target = set_param(page.url, name, "'")
            resp = ctx.http.get(target)
            if resp is None or not resp.text:
                continue
            if _DB_RE.search(resp.text) and not base_has_error:
                m = _DB_RE.search(resp.text)
                findings.append(Finding(
                    title=f"Database error triggered by input (parameter '{name}')",
                    severity=Severity.HIGH,
                    description=(
                        f"Supplying a syntax-breaking character in the '{name}' "
                        "parameter produced a database error that is absent from "
                        "the baseline response. This strongly indicates input is "
                        "passed into a SQL query without parameterisation "
                        "(SQL injection surface)."
                    ),
                    url=page.url,
                    owasp="A03",
                    stride=["T", "I", "E"],
                    cwe="CWE-89",
                    confidence=Confidence.MEDIUM,
                    evidence=f"DB error signature matched: {m.group(0)[:80]!r}",
                    remediation=(
                        "Use parameterised queries / prepared statements and an "
                        "allow-list for input. Never build SQL by string "
                        "concatenation."
                    ),
                    reference="https://owasp.org/www-community/attacks/SQL_Injection",
                    check_id=self.id,
                ))
        return findings
