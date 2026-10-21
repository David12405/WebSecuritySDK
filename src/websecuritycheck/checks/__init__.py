"""LAYER 2 - the check catalog.

One module per check, each registering a `Check` into `base.REGISTRY`.
Importing this package is what populates the registry, so every check module
has to be imported here - a check nobody imports is a check nobody can run.

The four of them look at one site between them, and the boundaries are
stated in each skill's `description`: a missing security header belongs to
`headers`, a cookie without `Secure` to `cookies`, and neither should report
the other's finding. A merged report counts a problem once.
"""

from .base import REGISTRY, Check, all_checks, get, register
from .cookies import COOKIES
from .cors import CORS
from .headers import HEADERS
from .tls import TLS

__all__ = [
    "COOKIES",
    "CORS",
    "HEADERS",
    "REGISTRY",
    "TLS",
    "Check",
    "all_checks",
    "get",
    "register",
]
