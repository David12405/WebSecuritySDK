"""Hard rule - may this call touch this target?

Three pure decisions live here, and a thin Strands hook will call the last
of them once there is an agent to attach it to:

    in_scope(target, scope)        is this URL one the developer owns?
    tool_allowed(name, allowlist)  is this tool one this check may use?
    guard_tool_call(name, input)   both of the above, on one proposed call

Pure on purpose. The decision has to be testable without an agent, reusable
by `examples/probe_target.py` with no model in the loop, and identical in
both places - a scope policy that only applies inside the agent loop is a
scope policy with a hole in it.

Neither function raises on a refusal. A refusal is an ordinary outcome that
the caller turns into `event.cancel_tool` plus an `ErrorInfo(kind="scope")`,
and `reason` is written to be read by whoever gets that report.

A bad *scope* is different: that is the developer's own configuration, wrong
before any target is involved, so `normalize_scope` raises `ValueError`
rather than quietly matching nothing.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

ALLOWED_SCHEMES = frozenset({"http", "https"})

DEFAULT_PORTS = {"http": 80, "https": 443}

#: Reasons are quoted back in `ErrorInfo.message` and in reports. A target
#: can be model-invented and arbitrarily long, so it is cut before it gets
#: anywhere near a log line.
MAX_QUOTED_CHARS = 120


@dataclass(frozen=True)
class ScopeDecision:
    """Allowed or not, and why not.

    `rule` is the numbered rule in ARCHITECTURE.md section 6 that refused,
    so a test can assert on the rule rather than on the wording of `reason`.
    """

    allowed: bool
    reason: str = ""
    rule: int | None = None

    def __bool__(self) -> bool:
        return self.allowed


ALLOWED = ScopeDecision(allowed=True)


@dataclass(frozen=True)
class ScopeEntry:
    """One normalized entry of the developer's scope."""

    scheme: str
    host: str
    port: int | None  # None means "not stated"; the scheme default applies
    path: str  # "" means the whole host

    @property
    def effective_port(self) -> int:
        return self.port if self.port is not None else DEFAULT_PORTS[self.scheme]


# --------------------------------------------------------------------------
# Scope configuration
# --------------------------------------------------------------------------


def normalize_scope(scope: Iterable[str]) -> list[ScopeEntry]:
    """Parse and validate the developer's scope, loudly.

    `scope=["myapp.com"]` is the mistake this exists to catch. With no
    scheme it parses as a path with no host, matches nothing, and every
    check fails with "host is not in scope" while the developer stares at a
    scope that plainly contains the host. Better to refuse at construction.
    """
    entries: list[ScopeEntry] = []
    for raw in scope:
        text = raw.strip()
        parts = urlsplit(text)
        if not parts.scheme:
            raise ValueError(f"scope entry {raw!r} has no scheme; write 'https://{text}'")
        if parts.scheme not in ALLOWED_SCHEMES:
            raise ValueError(f"scope entry {raw!r} must use http or https")
        try:
            hostname, port = parts.hostname, parts.port
        except ValueError as exc:  # urlsplit defers a bad port to .port
            raise ValueError(f"scope entry {raw!r} has an invalid port") from exc
        if not hostname:
            raise ValueError(f"scope entry {raw!r} has no host")
        entries.append(
            ScopeEntry(scheme=parts.scheme, host=_host(hostname), port=port, path=_path(parts.path))
        )
    return entries


# --------------------------------------------------------------------------
# Rules 1-6
# --------------------------------------------------------------------------


def in_scope(
    target: str,
    scope: Sequence[str] | Sequence[ScopeEntry],
    allow_subdomains: bool = False,
) -> ScopeDecision:
    """Is `target` inside `scope`?

    Rules, in the order ARCHITECTURE.md section 6 states them:

    1. the scheme is http or https
    2. the host matches - subdomains only when `allow_subdomains`
    3. an https -> http downgrade is refused
    4. ports must match when either side states one
    5. a scope path longer than `/` is a required prefix
    6. an empty scope matches nothing

    The target is allowed if *any* scope entry allows it. When none does,
    the reason returned is from the entry that got furthest: told "port 8443
    is not the scope port" a developer fixes the port, where "host is not in
    scope" about a host that is plainly listed sends them looking in the
    wrong place.
    """
    entries = _entries(scope)

    # Rule 6, first because an empty scope has no entry to report against.
    if not entries:
        return ScopeDecision(False, "the scope is empty, so no target is in scope", rule=6)

    parts = urlsplit(target.strip())

    # Rule 1. Decided here rather than left to the tool: the guard makes the
    # decision, so it must not depend on something else validating first.
    if parts.scheme not in ALLOWED_SCHEMES:
        return ScopeDecision(False, f"scheme {_quote(parts.scheme)!r} is not http or https", rule=1)
    try:
        hostname, target_port = parts.hostname, parts.port
    except ValueError:
        return ScopeDecision(False, f"{_quote(target)!r} has an invalid port", rule=1)
    if not hostname:
        return ScopeDecision(False, f"{_quote(target)!r} has no host", rule=1)

    host = _host(hostname)
    path = _path(parts.path)

    best: ScopeDecision | None = None
    for entry in entries:
        decision = _match(entry, parts.scheme, host, target_port, path, allow_subdomains)
        if decision.allowed:
            return ALLOWED
        if best is None or (decision.rule or 0) > (best.rule or 0):
            best = decision

    assert best is not None  # entries is non-empty, so the loop ran at least once
    return best


def _match(
    entry: ScopeEntry,
    scheme: str,
    host: str,
    port: int | None,
    path: str,
    allow_subdomains: bool,
) -> ScopeDecision:
    # Rule 2.
    if host != entry.host and not (allow_subdomains and host.endswith(f".{entry.host}")):
        return ScopeDecision(False, f"host {_quote(host)!r} is not in scope", rule=2)

    # Rule 3, deliberately before rule 4. http and https have different
    # default ports, so comparing ports first would refuse every downgrade
    # for the wrong reason - "port 80 is not the scope port 443" - and send
    # the developer off to fix a port that was never the problem.
    if entry.scheme == "https" and scheme == "http":
        return ScopeDecision(
            False,
            f"scope entry https://{entry.host} does not allow the http downgrade",
            rule=3,
        )

    # Rule 4. Two scheme defaults are compatible, which is what lets an
    # http -> https upgrade through.
    if (port is not None or entry.port is not None) and _port(scheme, port) != entry.effective_port:
        return ScopeDecision(
            False,
            f"port {_port(scheme, port)} is not the scope port {entry.effective_port}",
            rule=4,
        )

    # Rule 5. "/api" covers "/api" and "/api/v1", never "/apiary".
    if entry.path and path != entry.path and not path.startswith(f"{entry.path}/"):
        return ScopeDecision(
            False,
            f"path {_quote(path or '/')!r} is outside the scope path {entry.path!r}",
            rule=5,
        )

    return ALLOWED


# --------------------------------------------------------------------------
# Tool allowlist
# --------------------------------------------------------------------------


def tool_allowed(
    name: str,
    allowlist: Iterable[str],
    exempt: Iterable[str] = (),
) -> ScopeDecision:
    """May this check call this tool?

    `exempt` is the set of tools the framework injects rather than the check
    declaring them - the context manager's `retrieve_context`, and the
    structured-output tool, whose name is the check's own output model. They
    take no `target`, so there is nothing to scope-check, and cancelling
    them does not make a run safer: it costs the model its only way to read
    back offloaded tool output, or its only way to answer at all.

    Build the set with `memory.context.framework_tools_for(check.output_model)`.
    """
    if name in set(exempt) or name in set(allowlist):
        return ALLOWED
    return ScopeDecision(False, f"tool {_quote(name)!r} is not on this check's allowlist")


# --------------------------------------------------------------------------
# One proposed tool call - what the hook calls
# --------------------------------------------------------------------------


def guard_tool_call(
    name: str,
    tool_input: Mapping[str, Any],
    *,
    allowlist: Iterable[str],
    scope: Sequence[str] | Sequence[ScopeEntry],
    exempt: Iterable[str] = (),
    allow_subdomains: bool = False,
) -> ScopeDecision:
    """May this call run, given the arguments the model actually produced?

    This is everything `BeforeToolCall` has to decide. The hook itself only
    translates the answer into `event.cancel_tool(decision.reason)` and an
    `ErrorInfo` - keeping the Strands-shaped part down to a few lines, and
    this part testable with a dict.

    `tool_input` comes from the model, so it is checked rather than trusted.
    An absent `target`, or one that is not a string, is a refusal and never
    an exception: a guard that raises partway through is a guard whose
    behaviour depends on how the framework handles an exception in a hook,
    and that is not a question to leave open in the one component whose job
    is to stop a request reaching a host.

    Only `target` is scope-checked. Optional arguments like `origin` on
    `get_cors_policy` name an origin the probe *claims to be*, sent as a
    header - no request is made to it, so there is nothing to scope.
    """
    # Framework tools first: they take no `target`, so every check below
    # would refuse them for the wrong reason.
    if name in set(exempt):
        return ALLOWED

    allowed = tool_allowed(name, allowlist)
    if not allowed:
        return allowed

    if "target" not in tool_input:
        return ScopeDecision(
            False,
            f"tool {_quote(name)!r} was called without a 'target' argument, "
            "so the call cannot be scope-checked",
        )

    target = tool_input["target"]
    if not isinstance(target, str):
        return ScopeDecision(
            False,
            f"tool {_quote(name)!r} was called with a {type(target).__name__} target; "
            "the scope guard needs a single URL string",
        )
    if not target.strip():
        return ScopeDecision(False, f"tool {_quote(name)!r} was called with an empty target")

    return in_scope(target, scope, allow_subdomains)


# --------------------------------------------------------------------------
# Normalization
# --------------------------------------------------------------------------


def _entries(scope: Sequence[str] | Sequence[ScopeEntry]) -> list[ScopeEntry]:
    """Accept raw strings or an already-parsed scope.

    The hook parses the scope once per run rather than once per tool call,
    so it hands `ScopeEntry` objects straight back in.
    """
    if scope and isinstance(scope[0], ScopeEntry):
        return list(scope)  # type: ignore[arg-type]
    return normalize_scope(scope)  # type: ignore[arg-type]


def _host(hostname: str) -> str:
    """Lowercase, no trailing dot.

    `urlsplit` already lowercases, but `myapp.com.` and `myapp.com` are the
    same host in DNS and would otherwise compare unequal.
    """
    return hostname.rstrip(".").lower()


def _path(path: str) -> str:
    """`""` and `"/"` both mean the whole host; anything else keeps no trailing slash."""
    stripped = path.rstrip("/")
    return stripped if stripped not in {"", "/"} else ""


def _port(scheme: str, port: int | None) -> int:
    return port if port is not None else DEFAULT_PORTS[scheme]


def _quote(value: str) -> str:
    """Cut anything that will be repeated into a message.

    A target can arrive from the model, and a model can produce a megabyte
    of it. A reason string ends up in `ErrorInfo.message`, and from there in
    a report.
    """
    return value if len(value) <= MAX_QUOTED_CHARS else value[: MAX_QUOTED_CHARS - 1] + "…"
