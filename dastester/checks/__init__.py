"""Check registry.

Each check subclasses BaseCheck and registers itself. The scanner
discovers all registered checks and runs:
  - PASSIVE checks always,
  - ACTIVE checks when active scanning is enabled and authorised,
  - AGGRESSIVE checks only when --aggressive is also set.
"""

from .base import BaseCheck, PASSIVE, ACTIVE, AGGRESSIVE, registry

# Import check modules so their classes register on import.
from .passive import (  # noqa: F401
    security_headers,
    tls_checks,
    cookie_checks,
    info_disclosure,
    content_security,
    csrf,
    jwt_token,
    session_handling,
    http_methods,
    well_known,
)
from .active import (  # noqa: F401
    reflected_input,
    sql_error,
    sql_blind,
    stored_xss,
    open_redirect,
    directory_listing,
    cors,
    ssrf,
)
from .aggressive import (  # noqa: F401
    request_smuggling,
    ssrf_aggressive,
    access_control,
)

__all__ = ["BaseCheck", "PASSIVE", "ACTIVE", "AGGRESSIVE", "registry"]
