"""SQL injection tactic authoring (Stage A) and test planning (Stage B).

The bridge between Module 2's grounded hypotheses and Module 3's execution.
Two stages, deliberately separated:

- `stage_a` - tactic authoring. A control-plane operation: retrieve the OWASP
  WSTG methodology once, author a reusable, target-independent SQLi tactic,
  admit it through deterministic gates, and publish an immutable version. Runs
  only when no compatible tactic is already published.
- `stage_b` - validation planning. A runtime operation: combine one guarded
  hypothesis with the active tactic and trusted target context into a
  structured, per-hypothesis test plan for Module 3. Runs once per hypothesis.

`contracts` holds what both stages and Module 3 share: the SQLi safety policy
and the typed `HTTP_REQUEST` / `SQLI_DETECTION` capability contracts. No part of
this package sends traffic or decides a final verdict - a model never emits an
identifier, and code owns admission.
"""

from __future__ import annotations

from .contracts import (
    CAPABILITY_CONTRACTS,
    RiskProfile,
    SQLiSafetyPolicy,
    SQLiTechnique,
    capability_fingerprint,
)

__all__ = [
    "CAPABILITY_CONTRACTS",
    "RiskProfile",
    "SQLiSafetyPolicy",
    "SQLiTechnique",
    "capability_fingerprint",
]
