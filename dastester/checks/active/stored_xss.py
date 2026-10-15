"""Active check: stored/persistent XSS surface (correlation based).

Approach: for each crawled page with query parameters, inject a unique
inert marker into each parameter, then re-fetch *every other* crawled
page and the current one to see whether the marker surfaces un-encoded
somewhere it was not directly submitted. Persistence of an un-encoded
marker across pages indicates a stored-XSS surface.

To stay polite and bounded, the number of marker injections and the
re-scan set are capped. The marker is inert (it never executes); only its
reflection is observed.
"""

import secrets
from urllib.parse import urlparse

from ..base import BaseCheck, ACTIVE
from ...models import Finding, Severity, Confidence
from ._util import iter_param_mutations, set_param

_MAX_INJECTIONS = 15  # cap total injected params per scan for politeness


class StoredXssCheck(BaseCheck):
    id = "stored-xss"
    name = "Stored/persistent XSS surface"
    kind = ACTIVE
    owasp = "A03"
    stride = ["T", "S"]

    # Shared across pages within one scan run.
    _budget = {"n": 0}
    _reported = set()

    def run(self, page, ctx):
        findings = []
        if "?" not in page.url:
            return findings

        inject_path = urlparse(page.url).path

        # Candidate pages to re-check for persistence. Exclude the injection
        # endpoint's own path (re-fetching it would overwrite the marker with
        # its original benign value) and prefer parameter-less display pages,
        # which are the usual render targets for stored content.
        all_urls = list(ctx.pages.keys()) if getattr(ctx, "pages", None) else [page.url]
        recheck_urls = [u for u in all_urls if urlparse(u).path != inject_path]
        recheck_urls.sort(key=lambda u: ("?" in u, u))  # param-less first
        recheck_urls = recheck_urls[:25]  # bound

        seen = set()
        for name, _ in iter_param_mutations(page.url, ""):
            if name in seen or self._budget["n"] >= _MAX_INJECTIONS:
                continue
            seen.add(name)
            self._budget["n"] += 1

            token = "dynastore" + secrets.token_hex(4)
            probe = f"<{token}>"
            submit_url = set_param(page.url, name, probe)
            submitted = ctx.http.get(submit_url)
            if submitted is None:
                continue

            # Re-fetch candidate pages (fresh) and look for the marker.
            for url in recheck_urls:
                fresh = ctx.http.get(url)
                if fresh is None or not fresh.text:
                    continue
                raw = f"<{token}>" in fresh.text
                encoded = f"&lt;{token}&gt;" in fresh.text
                # Persistence: marker appears on a DIFFERENT page than submitted,
                # or remains on refetch of the same page, and is NOT encoded.
                if raw and not encoded:
                    key = (name, url)
                    if key in self._reported:
                        continue
                    self._reported.add(key)
                    persisted_elsewhere = url.split("?")[0] != page.url.split("?")[0]
                    findings.append(Finding(
                        title=f"Stored/persistent XSS surface (parameter '{name}')",
                        severity=Severity.HIGH if persisted_elsewhere else Severity.MEDIUM,
                        description=(
                            f"An inert marker injected into '{name}' on "
                            f"{page.url} was later returned un-encoded on "
                            f"{url}. Input appears to be stored and rendered "
                            "without output encoding (stored XSS surface)."
                        ),
                        url=url,
                        owasp="A03",
                        stride=["T", "S"],
                        cwe="CWE-79",
                        confidence=Confidence.MEDIUM if persisted_elsewhere else Confidence.LOW,
                        evidence=(
                            f"Marker '<{token}>' submitted at {page.url} "
                            f"re-observed un-encoded at {url}."
                        ),
                        remediation=(
                            "Apply context-aware output encoding when rendering "
                            "stored data, validate on input, and enforce a strict "
                            "Content-Security-Policy."
                        ),
                        reference="https://owasp.org/www-community/attacks/xss/",
                        check_id=self.id,
                    ))
        return findings
