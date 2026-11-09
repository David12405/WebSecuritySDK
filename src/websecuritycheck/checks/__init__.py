"""LAYER 2 - the check catalog.

One module per check, each registering a `Check` into `base.REGISTRY`.
Importing this package is what populates the registry, so every check module
has to be imported here - a check nobody imports is a check nobody can run.

They look at one site between them, and the boundaries are stated in each
skill's `description`: a missing security header belongs to `headers`, a
cookie without `Secure` to `cookies`, and neither should report the other's
finding. A merged report counts a problem once.

`surface` is registered but **parked** - `in_default_scan=False`, so
`check_all` does not run it. It is the multi-step recon check: fingerprint,
crawl, probe, browse, parse a spec - each step chosen from the last. A scan
of a site should not silently fan out into a crawl, so it runs by name only.
Its own module says why. WhatWeb lives here now, folded into the recon step,
rather than as a standalone `fingerprint` check that had to invent findings.
"""

from .base import REGISTRY, Check, all_checks, get, register, scan_checks
from .cookies import COOKIES
from .cors import CORS
from .headers import HEADERS
from .surface import SURFACE
from .tls import TLS

__all__ = [
    "COOKIES",
    "CORS",
    "HEADERS",
    "REGISTRY",
    "SURFACE",
    "TLS",
    "Check",
    "all_checks",
    "get",
    "register",
    "scan_checks",
]
