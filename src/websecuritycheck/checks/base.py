"""The `Check` definition and the registry.

A `Check` is the whole declarative description of one check, and it is what
step 2 of the turn diagram builds an agent from. Adding a check must need
nothing but one of these plus a skill folder - no change to the engine, the
policy layer or the public API. That is the acceptance criterion the shape
of this class exists to satisfy, so anything a check needs belongs here as
data rather than as a branch somewhere in the runner.

**The skill file is Strands' format, read by Strands' loader.** `Skill`
parses the `name` / `description` / `allowed-tools` frontmatter and the
markdown body, and `Skill.from_directory` would read a whole folder of them.
We use the type and skip the `AgentSkills` plugin that normally comes with
it - see `engine/prompts.system_prompt` for why.

`Skill.allowed_tools` is documented as experimental and not enforced, which
suits us: the allowlist the scope guard acts on is `Check.tools`, in code a
reviewer sees in a diff. The skill states it too so the method reads on its
own, and a test holds the two together.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import cache
from pathlib import Path

from strands.vended_plugins.skills import Skill

from ..results.models import CheckOutput

SKILLS_DIR = Path(__file__).resolve().parent.parent / "skills"


@dataclass(frozen=True)
class Check:
    """One check, as data."""

    name: str
    """`headers`, `cookies`, ... Also the public method suffix: `check_headers`."""

    task: str
    """What this check is asked to do, in the words the model reads."""

    tools: tuple[str, ...]
    """The allowlist. Every other tool is cancelled before it runs."""

    required_coverage: dict[str, list[str]] = field(default_factory=dict)
    """Topic -> other spellings of it.

    A topic counts as covered when its name or any alias appears. Aliases
    exist because not every topic is a literal string a model writes: no
    model writes "expiry", it writes "expires in 71 days" or quotes
    `not_after`. Draw them from the tool's own field names first - those are
    fixed by the contract - and only then from how a model phrases things.
    """

    skill: str = ""
    """Folder under `skills/`. Defaults to `name`."""

    output_model: type[CheckOutput] = CheckOutput
    """The structured-output schema. Its class name is also the name of the
    tool Strands injects for it, which is why the exempt set is per check."""

    max_turns: int = 6
    """A loop that has not answered in this many turns is not about to."""

    @property
    def skill_name(self) -> str:
        return self.skill or self.name

    @property
    def skill_path(self) -> Path:
        return SKILLS_DIR / self.skill_name / "SKILL.md"

    def skill_doc(self) -> Skill:
        """The parsed SKILL.md, read once per process."""
        return _load_skill(self.skill_path)

    def skill_text(self) -> str:
        """Just the method - what goes into the prompt."""
        return self.skill_doc().instructions

    @property
    def coverage_topics(self) -> tuple[str, ...]:
        return tuple(self.required_coverage)


@cache
def _load_skill(path: Path) -> Skill:
    """Read and parse one SKILL.md, once per process.

    `strict=True` on purpose. Strands defaults to warning and loading the
    file anyway, which is right for a general agent discovering skills it
    did not write - but here a malformed skill means a check runs with no
    method, and that is a packaging error worth refusing rather than a
    degraded mode worth tolerating.
    """
    if not path.exists():
        raise FileNotFoundError(f"check skill not found: {path}")
    return Skill.from_file(path, strict=True)


REGISTRY: dict[str, Check] = {}


def register(check: Check) -> Check:
    """Put a check in the registry. Duplicate names are a programming error."""
    if check.name in REGISTRY:
        raise ValueError(f"a check named {check.name!r} is already registered")
    REGISTRY[check.name] = check
    return check


def get(name: str) -> Check:
    if name not in REGISTRY:
        known = ", ".join(sorted(REGISTRY)) or "none"
        raise KeyError(f"unknown check {name!r}; registered: {known}")
    return REGISTRY[name]


def all_checks() -> tuple[Check, ...]:
    return tuple(REGISTRY[name] for name in sorted(REGISTRY))
