"""Base class and registry for DASTester checks."""

from __future__ import annotations

from typing import List

PASSIVE = "passive"
ACTIVE = "active"
AGGRESSIVE = "aggressive"

# Registry of check classes, populated by __init_subclass__.
registry: List[type] = []


class BaseCheck:
    """Base class for all checks.

    Subclasses set:
      id          - stable short identifier
      name        - human readable name
      kind        - PASSIVE or ACTIVE
      owasp       - default OWASP Top 10 category key
      stride      - default list of STRIDE codes

    and implement run(page, ctx) -> list[Finding].

    PASSIVE checks only read responses already fetched by the crawler.
    ACTIVE checks may send additional, non-destructive requests through
    ctx.http. Active checks must stay safe: read-only intent, bounded
    request count, and no payloads designed to alter or damage data.
    AGGRESSIVE checks are active checks that carry a real risk of
    disrupting live traffic (e.g. request-smuggling probes) and only run
    when the operator passes --aggressive in addition to authorisation.

    Checks may read ``ctx.pages`` (all crawled pages, keyed by URL) for
    cross-page correlation, e.g. stored-XSS detection.
    """

    id: str = "base"
    name: str = "Base check"
    kind: str = PASSIVE
    owasp: str = "A05"
    stride: List[str] = ["I"]

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if getattr(cls, "id", "base") != "base":
            registry.append(cls)

    def run(self, page, ctx):
        raise NotImplementedError
