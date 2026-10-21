"""WebSecurityCheck SDK - public surface.

Only the entry point and the result types are public. Everything else in
this package is internal and may change without notice.

    from websecuritycheck import SecurityChecker

    checker = SecurityChecker(model="openai:gpt-4o-mini", scope=["https://myapp.com"])
    result = checker.check_headers(target="https://myapp.com")

    result.status     # passed | issues_found | partial | failed
    result.findings   # problems in the target
    result.errors     # failures of the SDK, a tool, or the model
    result.trace      # every step the agent took
"""

#: Reported in every SARIF export, so a report says which SDK produced it.
#: Kept in step with `version` in pyproject.toml.
#:
#: Defined **before** the re-exports below, and that order is load-bearing.
#: `results/export.py` reads this name, and it is imported as part of the
#: chain those lines start - so a version assigned after them is not there
#: yet when the chain asks for it.
__version__ = "0.1.0"

from .checker import SecurityChecker
from .results.models import (
    CheckResult,
    ErrorInfo,
    Finding,
    RunDiff,
    TraceStep,
)

__all__ = [
    "CheckResult",
    "ErrorInfo",
    "Finding",
    "RunDiff",
    "SecurityChecker",
    "TraceStep",
    "__version__",
]
