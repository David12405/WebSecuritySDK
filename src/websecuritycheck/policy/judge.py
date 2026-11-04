"""The fourth steering rule: a second model reads the answer against the skill.

The three rules next door compare strings. They hold every time and they
cannot judge, and both halves of that sentence matter.

**What only a judge can catch.** The parked `fingerprint` check produced
`location="Title"`, `evidence="Internal Admin"`, severity high. Both strings
were really in the tool output, so grounding passed it - and the finding was
still wrong, because a page title is not evidence that an admin interface
exists. "Does this conclusion follow from this evidence?" is a judgement, and
no amount of token matching answers it.

**What a judge must never be trusted with.** It agrees with itself at a
rate: measured on this project, one check and one target over three
identical runs gave three different answers. So the judge may only **add**
issues. It cannot clear one the deterministic rules raised, and `review()`
in `steering` composes them in that order for that reason. A judge that
could overrule grounding would let an invented finding through on the run
where it happened to be lenient, and the whole point of the deterministic
half is that there is no such run.

**The judge reads the skill.** That is what makes it worth the call. The
skill is the agreed method - written by whoever owns the security knowledge,
not by the harness - so asking "was this method followed" is asking the only
question the harness itself has no opinion about.

**The judge is as injectable as the model it is judging.** It is shown tool
output, which came from the target, so it gets the same framing the main
model gets: the same banner, the same per-run nonce, the same closing line.
A second model reading unlabelled target text would be a second way in, and
it would be the one nobody was watching.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field
from strands import Agent

from ..checks.base import Check
from ..results.models import CheckOutput
from .injection_guard import trim, wrap

#: One judging call, and a small model is enough: this is a reading task
#: over text already in front of it, not a security analysis.
JUDGE_MAX_TURNS = 1

#: The judge sees less target data than the main model. It is checking the
#: answer against the method, not measuring anything, and a long corpus buys
#: nothing but tokens.
JUDGE_CORPUS_CHARS = 6_000

JUDGE_SYSTEM = """\
You review the findings in one security check's answer against the method it
was told to follow.

**You object to findings that are there. You never ask for more.** Not a
topic covered too briefly, not a question left open, not a check that could
have gone further. Those are somebody else's rule, and a reviewer who asks a
security tool for more findings gets more findings - invented ones, written
to satisfy you.

Report a problem only when you can name the finding it is about and say what
is wrong with that finding. Two things qualify:

**follows** - the evidence does not support the claim. The evidence is real
and the conclusion does not come from it. Text the target chose - a page
title, body copy, a meta tag - is not evidence that something exists; a tool
naming a component is. This is the one worth your attention.

**method** - the skill states a rule and this finding breaks it. The skill
is the agreed method and it outranks what you know about security generally.
If it says a page title is never evidence, a finding resting on one breaks
the method even if you would have reported it too.

An empty list is the normal result and the right one for a good answer. An
answer with no findings at all has nothing for you to object to: return an
empty list.

Findings carry no severity and how much a problem matters is not yours to
rate. Say whether the finding is supported, not how bad it is."""


class JudgeIssue(BaseModel):
    """One problem the judge found, in the words the author needs."""

    model_config = ConfigDict(extra="forbid")

    rule: Literal["follows", "method"]
    """The two objections a judge may raise. A closed set rather than a
    string, because the first version advertised a third rule - `substance`,
    "a topic named but not addressed" - in this description after it had
    been dropped from the system prompt. The model reads the schema, so it
    kept raising it."""

    subject: str = Field(description="The title of the finding this is about.")
    detail: str = Field(description="What is wrong and what to change, addressed to the author.")


class JudgeVerdict(BaseModel):
    """The judge's whole contribution.

    `extra="forbid"` for the same reason `CheckOutput` has it: a model that
    has seen enough review tools will helpfully add a `score` or an
    `approved` field, and a later refactor that reads one would hand the
    judge a veto it was never meant to have.
    """

    model_config = ConfigDict(extra="forbid")

    issues: list[JudgeIssue] = Field(default_factory=list)


def _answer_for_review(output: CheckOutput) -> str:
    """The answer, laid out so a reader can point at one finding.

    There is no severity to show. There was, and the judge argued it on
    every finding of a live run while justifying itself with "the site
    handles credentials or sessions" - no evidence for it, and not true of
    the target. Hiding the field stopped the argument; dropping it from
    `FindingDraft` removed the question, which is the better fix and the
    one the project made.
    """
    if not output.findings:
        lines = ["FINDINGS: none"]
    else:
        lines = ["FINDINGS:"]
        for index, draft in enumerate(output.findings, start=1):
            lines += [
                f"  [{index}] {draft.title}",
                f"      location:  {draft.location}",
                f"      evidence:  {draft.evidence}",
                f"      from tool: {draft.source_tool or '(unattributed)'}",
            ]
    lines += ["", f"NOTES: {output.notes or '(empty)'}"]
    return "\n".join(lines)


def judge_prompt(check: Check, output: CheckOutput, corpus: str, nonce: str) -> str:
    """Everything the judge reads, with the target's bytes labelled as such.

    The corpus goes through the same `wrap` the main model's tool results
    go through. It is the same text from the same target, and the only
    difference here is that nobody would have thought to check.
    """
    skill = check.skill_doc()
    cut, truncated = trim(corpus, JUDGE_CORPUS_CHARS)
    return "\n\n".join(
        [
            f"## The method ({skill.name})",
            skill.instructions.strip(),
            "## The required topics",
            ", ".join(check.coverage_topics) or "(none declared)",
            "## What the tools returned",
            wrap("tool results", cut, nonce, truncated=truncated),
            "## The answer under review",
            _answer_for_review(output),
            "List the problems. An empty list is the normal result.",
        ]
    )


def judge(
    check: Check,
    output: CheckOutput,
    corpus: str,
    nonce: str,
    model: Any,
) -> list[JudgeIssue]:
    """Run the judge. Returns no issues rather than raising, ever.

    A judge that breaks the run would be worse than no judge: it is the
    optional half, and a model call that times out or returns malformed
    output must cost the run nothing but the call. The deterministic rules
    have already had their say by the time this is reached.
    """
    if not corpus.strip():
        return []  # nothing measured; the status rule owns that case
    try:
        agent = Agent(
            model=model,
            tools=[],
            system_prompt=JUDGE_SYSTEM,
            structured_output_model=JudgeVerdict,
            callback_handler=None,
        )
        prompt = judge_prompt(check, output, corpus, nonce)
        result = agent(prompt, limits={"turns": JUDGE_MAX_TURNS})
    except Exception:
        return []
    verdict = result.structured_output
    if not isinstance(verdict, JudgeVerdict):
        return []
    return _about_a_finding(verdict.issues, output)


def _about_a_finding(issues: Sequence[JudgeIssue], output: CheckOutput) -> list[JudgeIssue]:
    """Keep only the objections that name a finding the answer actually has.

    The prompt says the judge may object to findings and never ask for
    more. This is the same rule in code, because a prompt-level rule holds
    at a rate and this one has to hold every time.

    Measured on the first live run with the judge enabled: told it could
    raise a topic "named but not addressed", it raised one on every check,
    on every round, and `tls` came back with an invented `info` finding
    that had not been there before. A reviewer who can ask a security tool
    for more findings gets more findings.

    Matched loosely - a judge writing `Missing CSP header` about
    `Missing Content-Security-Policy header` means the one finding in
    front of it - because the cost of the two errors is not symmetric. A
    dropped real objection is a `follows` problem nobody hears about; a
    kept invented one is pressure to write a finding.
    """
    titles = [draft.title.lower() for draft in output.findings]
    if not titles:
        return []  # nothing to object to, and nothing to ask for
    kept = []
    for issue in issues:
        subject = issue.subject.lower().strip()
        if any(subject in title or title in subject for title in titles):
            kept.append(issue)
    return kept
