"""LAYER 2 - the check catalog.

One module per check, each registering a `Check` into `base.REGISTRY`.
Importing this package is what populates the registry, so every check module
has to be imported here - a check nobody imports is a check nobody can run.
"""

from .base import REGISTRY, Check, all_checks, get, register
from .headers import HEADERS

__all__ = ["HEADERS", "REGISTRY", "Check", "all_checks", "get", "register"]
