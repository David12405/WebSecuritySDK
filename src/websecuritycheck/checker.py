"""LAYER 1 - the public API.  Step 1 of the turn diagram.

The whole SDK, from a developer's side:

    checker = SecurityChecker(model="openai:gpt-4o-mini", scope=["https://myapp.com"])
    result = checker.check_headers(target="https://myapp.com")

One typed method per check. No prompt is written by the caller, no `strands`
import appears in their code, and the result is a `CheckResult` whose status
the model had no say in.

The methods are thin by design: each one names a check and hands it to the
runner. Adding a check should mean adding a `Check` and a skill folder, and
the only thing that belongs here is one more three-line method.
"""

from __future__ import annotations

from pathlib import Path

from .checks import base as checks
from .config import Settings
from .engine.runner import run_check
from .results.models import CheckResult


class SecurityChecker:
    """The entry point. One instance per model and scope."""

    def __init__(
        self,
        model: str,
        scope: list[str],
        *,
        allow_subdomains: bool = False,
        trace_level: str = "summary",
        servers_config: str | Path | None = None,
        api_key: str | None = None,
        temperature: float = 0.0,
    ) -> None:
        """Scope is required and is validated here.

        A malformed scope entry - `"myapp.com"` with no scheme - raises now,
        where the developer can see it, rather than matching nothing and
        failing every check later with "host is not in scope".
        """
        kwargs = {}
        if servers_config is not None:
            kwargs["servers_config"] = Path(servers_config)
        self.settings = Settings(
            model=model,
            scope=list(scope),
            allow_subdomains=allow_subdomains,
            trace_level=trace_level,
            api_key=api_key,
            temperature=temperature,
            **kwargs,
        )

    # -- the checks -------------------------------------------------------

    def check_headers(self, target: str) -> CheckResult:
        """HSTS, CSP, X-Frame-Options, X-Content-Type-Options, and what leaks."""
        return self.run("headers", target)

    def check_all(self, target: str) -> list[CheckResult]:
        """Every registered check, merged into one list of results."""
        return [self.run(check.name, target) for check in checks.all_checks()]

    # -- the seam ---------------------------------------------------------

    def run(self, check_name: str, target: str) -> CheckResult:
        """Run a check by name.

        Public because a caller adding their own `Check` should not have to
        wait for a method here, and because `check_all` needs it anyway.
        """
        return run_check(checks.get(check_name), target, self.settings)

    @property
    def checks(self) -> tuple[str, ...]:
        return tuple(check.name for check in checks.all_checks())
