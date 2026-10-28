"""Settings - model, scope, limits, server list.

Deliberately free of any `strands` import. The model is carried as a
`"provider:model-id"` string and `engine/models.py` is the one place that
turns it into a provider object, which is what keeps the dependency on an
agent framework out of the SDK's own configuration.

Scope is required. There is no default and no "scan anything" mode: the one
setting that decides what this SDK is allowed to touch is not one to have a
convenient default for.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .policy.scope_guard import ScopeEntry, normalize_scope

REPO_ROOT = Path(__file__).resolve().parents[2]

DEFAULT_SERVERS = REPO_ROOT / "config" / "servers.yaml"


@dataclass
class Settings:
    """Everything a run needs that is not the target."""

    model: str
    """`"provider:model-id"`, e.g. `"openai:gpt-4o-mini"`. A bare string with
    no known prefix is read as a Bedrock model id."""

    scope: list[str]
    """URLs this SDK may contact. Required; an empty scope matches nothing."""

    allow_subdomains: bool = False
    trace_level: str = "summary"  # off | summary | full

    servers_config: Path = DEFAULT_SERVERS
    """Which MCP servers to connect to."""

    api_key: str | None = None
    """Normally unset: each provider SDK reads its own environment variable.
    Present for a demo where passing one explicitly is simpler."""

    temperature: float = 0.0
    """A security report that changes between identical runs is worse than a
    strict one. Zero by default for the same reason steering is
    deterministic."""

    use_judge: bool = False
    """Run the model-judged steering rule as well as the deterministic ones.

    It catches the one thing string matching cannot - a finding whose
    evidence is real and does not support it - and on the parked
    `fingerprint` check it caught exactly that, twice out of two runs,
    naming the finding that rested on a page title.

    **Off by default because it is measurably harmful on the checks whose
    answers were already correct.** On `headers` it argued severity on all
    four findings and invented a premise to justify it ("the site handles
    credentials or sessions", of a target with no forms and no cookies);
    hiding severity from it stopped that and it then pressured the model
    into merging four specific findings into one vague one. Three rounds of
    narrowing its remit moved the noise rather than removing it.

    So it is a tool for a check that needs judgement, not a default. The
    deterministic rules run either way, and the judge can only add issues,
    never clear one - turning it on cannot loosen a boundary, only spend
    model calls and risk a worse answer."""

    _entries: list[ScopeEntry] = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        if not self.scope:
            raise ValueError(
                "scope is required: pass the targets you own, e.g. "
                "scope=['https://myapp.com']. There is no scan-anything mode."
            )
        # Parses and validates now, so a malformed scope is the caller's
        # error at construction rather than a confusing block mid-run.
        self._entries = normalize_scope(self.scope)

    @property
    def entries(self) -> list[ScopeEntry]:
        """The parsed scope, built once and reused by every tool call."""
        return self._entries
