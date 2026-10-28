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
        use_judge: bool = False,
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
            use_judge=use_judge,
            **kwargs,
        )

    # -- the checks -------------------------------------------------------

    def check_headers(self, target: str) -> CheckResult:
        """HSTS, CSP, X-Frame-Options, X-Content-Type-Options, and what leaks."""
        return self.run("headers", target)

    def check_tls(self, target: str) -> CheckResult:
        """Chain trust, name match, expiry, protocol and cipher. Needs https."""
        return self.run("tls", target)

    def check_cookies(self, target: str) -> CheckResult:
        """Secure, HttpOnly, SameSite, scope and lifetime, per cookie."""
        return self.run("cookies", target)

    def check_cors(self, target: str) -> CheckResult:
        """Which origins may read the response, and whether credentials go with them."""
        return self.run("cors", target)

    def check_fingerprint(self, target: str) -> CheckResult:
        """Published versions and components that should not be reachable.

        Needs the WhatWeb binary. Without it the check comes back `failed`
        with `E_TOOL_UNAVAILABLE` - a fact about the machine, not the
        target. See `scripts/README.md`.
        """
        return self.run("fingerprint", target)

    def check_all(self, target: str) -> list[CheckResult]:
        """What a scan of a site means today, merged into one list of results.

        Parked checks are left out. `checks` lists everything that can be
        run by name, which is the larger set.
        """
        return [self.run(check.name, target) for check in checks.scan_checks()]

    # -- the seam ---------------------------------------------------------

    def run(self, check_name: str, target: str) -> CheckResult:
        """Run a check by name.

        Public because a caller adding their own `Check` should not have to
        wait for a method here, and because `check_all` needs it anyway.
        """
        return run_check(checks.get(check_name), target, self.settings)

    @property
    def checks(self) -> tuple[str, ...]:
        """Everything runnable by name, parked checks included."""
        return tuple(check.name for check in checks.all_checks())

    @property
    def scan_checks(self) -> tuple[str, ...]:
        """What `check_all` would run."""
        return tuple(check.name for check in checks.scan_checks())
