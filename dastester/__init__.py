"""DASTester - a dynamic application security testing (DAST) scanner.

DASTester performs runtime security checks against HTTP/HTTPS web
applications, categorises findings against the OWASP Top 10 (2021),
maps them onto the STRIDE threat model, and produces HTML and PDF
reports.

DASTester is an authorised-testing tool. Only scan systems you own or
have explicit written permission to test.
"""

from .__version__ import __version__

__all__ = ["__version__"]
