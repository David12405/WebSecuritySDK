"""The `Check` definition and the registry.

A `Check` is the whole declarative description of one check, and it is what
step 2 of the turn diagram builds an agent from. Adding a check must need
nothing but one of these plus a skill folder - no change to the engine, the
policy layer or the public API. That is the acceptance criterion the shape
of this class exists to satisfy, so anything a check needs belongs here as
data rather than as a branch somewhere in the runner.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from typing import Any

import yaml

from ..results.models import CheckOutput

SKILLS_DIR = Path(__file__).resolve().parent.parent / "skills"

#: A SKILL.md opens with a YAML block between `---` lines.
FRONTMATTER = re.compile(r"\A---\s*\n(.*?)\n---\s*\n(.*)\Z", re.DOTALL)


@dataclass(frozen=True)
class SkillDoc:
    """One SKILL.md: a small header the harness reads, and the method itself.

    The split follows the convention a skill file is normally written in -
    `name`, `description` and `allowed-tools` are metadata a selector can
    read cheaply, and the body is the instructions.

    This SDK does not select: the developer calls `check_headers`, so the
    harness knows which skill applies before an agent exists, and the body
    goes into the prompt in full. The header is still worth having. It makes
    the file self-describing to a reader who is not reading our Python, it
    gives `check_all` and any future catalog a one-line summary, and
    `allowed_tools` written next to the method is a second statement of the
    allowlist that a test can hold against the `Check`.
    """

    name: str
    description: str
    allowed_tools: tuple[str, ...]
    body: str
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def parse(cls, text: str, *, source: Path | None = None) -> SkillDoc:
        match = FRONTMATTER.match(text)
        if not match:
            raise ValueError(
                f"{source or 'skill'} has no YAML frontmatter; a SKILL.md opens with "
                "`---`, then name/description/allowed-tools, then `---`"
            )
        header = yaml.safe_load(match.group(1)) or {}
        if not isinstance(header, dict):
            raise ValueError(f"{source or 'skill'}: frontmatter must be a mapping")

        missing = [key for key in ("name", "description") if not header.get(key)]
        if missing:
            raise ValueError(f"{source or 'skill'}: frontmatter is missing {', '.join(missing)}")

        # Accept either spelling; the file is written by hand and the dash
        # and the underscore are equally easy to type.
        tools = header.get("allowed-tools", header.get("allowed_tools")) or []
        if isinstance(tools, str):
            tools = [tools]

        return cls(
            name=str(header["name"]),
            description=" ".join(str(header["description"]).split()),
            allowed_tools=tuple(str(tool) for tool in tools),
            body=match.group(2).strip(),
            metadata={
                key: value
                for key, value in header.items()
                if key not in {"name", "description", "allowed-tools", "allowed_tools"}
            },
        )


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

    def skill_doc(self) -> SkillDoc:
        """The parsed SKILL.md, read once per process."""
        return _load_skill(self.skill_path)

    def skill_text(self) -> str:
        """Just the method - what goes into the prompt."""
        return self.skill_doc().body

    @property
    def coverage_topics(self) -> tuple[str, ...]:
        return tuple(self.required_coverage)


@cache
def _load_skill(path: Path) -> SkillDoc:
    """Read and parse one SKILL.md.

    A missing or malformed skill is a packaging error rather than a runtime
    condition - the folder ships inside the wheel - so it raises here
    instead of quietly running a check with no method.
    """
    if not path.exists():
        raise FileNotFoundError(f"check skill not found: {path}")
    return SkillDoc.parse(path.read_text(encoding="utf-8"), source=path)


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
