"""Active check: robust error-based and parameterised SQL injection detection."""

import re
from ..base import BaseCheck, ACTIVE
from ...models import Finding, Severity, Confidence
from ._util import iter_param_mutations, set_param

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
]
_DB_RE = re.compile("|".join(_DB_ERRORS), re.I)


class SqlErrorCheck(BaseCheck):
    id = "sql-error"
    name = "SQL Injection Vulnerability Check"
    kind = ACTIVE
    owasp = "A03:2021"
    stride = ["T", "I", "E"]

    def run(self, page, ctx):
        findings = []
        if "?" not in page.url:
            return findings
            
        base_has_error = bool(_DB_RE.search(page.body or ""))
        seen = set()

        for name, _ in iter_param_mutations(page.url, ""):
            if name in seen:
                continue
            seen.add(name)

            # Test multiple inert syntax probes
            for probe in ["'", "\"", "' OR '1'='1"]:
                target = set_param(page.url, name, probe)
                resp = ctx.http.get(target)
                if resp is None or not resp.text:
                    continue

                match = _DB_RE.search(resp.text)
                if match and not base_has_error:
                    findings.append(Finding(
                        title=f"SQL Injection Vulnerability Found in Parameter '{name}'",
                        severity=Severity.CRITICAL,
                        description=(
                            f"The input field '{name}' accepts raw database commands without "
                            "proper sanitisation. When tested with a syntax probe, the database "
                            "returned an explicit error message exposing its internal structure."
                        ),
                        url=page.url,
                        owasp="A03:2021",
                        stride=["T", "I", "E"],
                        cwe="CWE-89",
                        attack_vector="Network",
                        exploitability="Easy",
                        auth_required="No",
                        confidence=Confidence.HIGH,
                        evidence=f"Database error signature triggered: {match.group(0)}",
                        remediation=(
                            "Rewrite database queries to use Parameterised Queries or Prepared Statements. "
                            "Never concatenate raw user input directly into SQL strings."
                        ),
                        reference="https://owasp.org/www-community/attacks/SQL_Injection",
                        check_id=self.id,
                    ))
                    break
        return findings
