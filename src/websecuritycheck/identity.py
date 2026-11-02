"Deterministic identities shared by canonical entities and reports."

from __future__ import annotations

import hashlib


def stable_hash(*parts: str) -> str:
    """Return the short deterministic digest for canonical identity parts."""

    payload = "|".join(parts).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:12]
