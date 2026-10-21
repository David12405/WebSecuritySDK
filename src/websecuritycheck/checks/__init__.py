"""LAYER 2 - the check catalog.

One module per check, each registering a `Check` into `base.REGISTRY`.
Importing this package is what populates the registry, so every check module
has to be imported here - a check nobody imports is a check nobody can run.

They look at one site between them, and the boundaries are stated in each
skill's `description`: a missing security header belongs to `headers`, a
cookie without `Secure` to `cookies`, and neither should report the other's
finding. A merged report counts a problem once.

`fingerprint` is registered but **parked** - `in_default_scan=False`, so
`check_all` does not run it. It belongs to a shape that does not exist yet:
reconnaissance that feeds a router, rather than a check that returns a
verdict. Its own module says why, and the reason is measured rather than
argued.
"""

from .base import REGISTRY, Check, all_checks, get, register, scan_checks
from .cookies import COOKIES
from .cors import CORS
from .fingerprint import FINGERPRINT
from .headers import HEADERS
from .tls import TLS

__all__ = [
    "COOKIES",
    "CORS",
    "FINGERPRINT",
    "HEADERS",
    "REGISTRY",
    "TLS",
    "Check",
    "all_checks",
    "get",
    "register",
    "scan_checks",
]
