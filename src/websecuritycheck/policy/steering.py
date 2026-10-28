"""Soft rules - the two orange boxes in the diagram.

Three rules read the answer once it exists and, when one fails, send the
model back with the specific thing it has to fix. They are soft in the sense
that the model gets to answer again rather than being overruled; they are
not soft in the sense of being vague.

coverage   every topic in `check.required_coverage` is addressed
grounding  every finding's location appears in some tool result this run
evidence   every finding quotes something, not a restatement of its title

**Deterministic only, and that is a decision rather than a simplification.**
An LLM judge reads intent better than a string match ever will, and it
agrees with itself at a rate. Measured on this project: one check, one
target, three identical runs, three different answers. A rate is fine for a
suggestion and useless for a rule, and a security SDK that changes its mind
between runs is worse than one that is predictably strict. The rules here
can be written down, so they can be regression tested, so they hold.

**What these rules do not catch.** Grounding asks whether a finding rests on
something a tool returned - it has nothing to say about whether the finding
*follows* from it. The parked `fingerprint` check produced
`location="Title", evidence="Internal Admin"` and both strings were really
in the tool output; the finding was wrong because a page title is not
evidence of an admin interface. That is a different failure, it needs a
different mechanism, and reaching for steering to fix it would only make
steering look broken. Invention is what grounding catches.

**Matching is token-based, not substring.** The `tls` skill writes a
location as `example.com:443` while the probe returns `hostname` and `port`
as separate fields, so `"example.com:443" in corpus` is False for a
perfectly good finding. Comparing the tokens instead - `example`, `com`,
`443` - asks the question that was meant: does this location name things
the tool actually said? A rule that fails on correct answers costs more than
the one it was written to catch.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from ..checks.base import Check
from ..results.models import CheckOutput, FindingDraft
from .judge import JudgeIssue

#: Tokens shorter than this are dropped before matching. Below three
#: characters a token matches almost anything - `a`, `is`, `80` - and a rule
#: that always passes is a rule nobody can rely on.
MIN_TOKEN = 3

#: How many times a run will send the answer back. Two is the point where
#: the model has seen the rule, been told it still fails, and tried again;
#: beyond that it tends to restate rather than fix, while every round costs
#: a model call and turns from the check's budget.
MAX_ROUNDS = 2

_WORD = re.compile(r"[a-z0-9]+")


@dataclass(frozen=True)
class SteeringIssue:
    """One rule, unmet, in the words the model needs to act on."""

    rule: str
    """`coverage`, `grounding` or `evidence`. Also the trace step name."""

    detail: str
    """What is wrong and what to do about it, addressed to the model."""

    subject: str = ""
    """The topic or finding title this is about, for the trace."""


def tokens(text: str, min_len: int = MIN_TOKEN) -> set[str]:
    """Lowercase alphanumeric runs, short ones dropped.

    `min_len` is a parameter because the two rules that use this want
    opposite things from it. Grounding asks whether a location names
    something a tool said, and there a two-character token matches almost
    any result - `443`, `com` and `and` would all count as evidence of
    nothing. The evidence rule asks whether a quote adds anything the title
    did not have, and there the short tokens are the whole point: against
    the title `Version disclosure of Apache`, the quote `Apache/2.4.29`
    adds exactly `2`, `4` and `29`. Dropping them deletes the version
    number and leaves the rule calling a real quote a restatement - which
    is what it did on the first live run.
    """
    return {word for word in _WORD.findall(text.lower()) if len(word) >= min_len}


def _answer_text(output: CheckOutput) -> str:
    """Everything the model said, as one string.

    Coverage is a question about the answer rather than about the findings:
    a check that establishes a certificate is nowhere near expiry has
    addressed expiry, and the right place for that is `notes`. Reading only
    findings would demand a finding for every topic, which is a demand for
    findings that do not exist.
    """
    parts = [output.notes]
    for draft in output.findings:
        parts += [draft.title, draft.location, draft.evidence]
    return "\n".join(parts).lower()


# --------------------------------------------------------------------------
# The three rules
# --------------------------------------------------------------------------


def check_coverage(output: CheckOutput, required: dict[str, list[str]]) -> list[SteeringIssue]:
    """Did the answer address every topic the check declares?

    A topic counts as addressed when its own name or any alias appears
    anywhere in the answer. Crude on purpose: the alternative is judging
    whether a topic was addressed *in substance*, which is the LLM judge
    this module exists to avoid. The crude version catches the failure that
    actually happens - the model answering about two of three topics and
    never mentioning the third.
    """
    text = _answer_text(output)
    issues = []
    for topic, aliases in required.items():
        spellings = [topic, topic.replace("_", " "), *aliases]
        if any(spelling.lower() in text for spelling in spellings):
            continue
        issues.append(
            SteeringIssue(
                rule="coverage",
                subject=topic,
                detail=(
                    f"You did not address {topic!r}. The skill requires it, and the "
                    "answer does not mention it in any form. Say what the tool result "
                    "shows about it - in `notes` if it is not a problem, as a finding "
                    "if it is. Do not invent one to satisfy this."
                ),
            )
        )
    return issues


def check_grounding(findings: Sequence[FindingDraft], corpus: str) -> list[SteeringIssue]:
    """Does each finding name something a tool actually returned?

    A finding whose location shares no vocabulary with any tool result was
    not measured, and an unevidenced finding is the one failure mode that
    makes a security report actively harmful.

    An empty corpus means nothing was archived - no tool ran, or every
    result was exempt - and the rule abstains rather than failing every
    finding. "No tool ran" is already the status rule's job, and two
    mechanisms reporting one problem in different words helps nobody.
    """
    if not corpus.strip():
        return []
    available = tokens(corpus)
    issues = []
    for draft in findings:
        wanted = tokens(draft.location)
        # Every token, not any. One shared token grounds nothing: against a
        # result about `example.com`, the invented location
        # `admin.example.net:8443` shares `example` and passes, which is the
        # exact finding this rule exists to catch. Calibrated against the
        # locations real runs produce - `content-security-policy`,
        # `example.com:443` - which the skills require be spelled the way
        # the tool spelled them, so every word has a source.
        if not wanted or wanted <= available:
            continue
        issues.append(
            SteeringIssue(
                rule="grounding",
                subject=draft.title,
                detail=(
                    f"The finding {draft.title!r} is about {draft.location!r}, and no "
                    "tool result this run mentions it. Either quote the result that "
                    "does, or drop the finding. Report what this run measured, not "
                    "what sites like this usually get wrong."
                ),
            )
        )
    return issues


def check_tools_used(tools_seen: set[str], must_call: Sequence[str]) -> list[SteeringIssue]:
    """Did the run use every tool a complete answer needs?

    The status rule next door only asks whether *any* tool ran, which is
    the same question while every check declares one tool and stops being
    the same question the moment one declares two. A check that reads
    headers and cookies and only ever called headers has measured
    something, and has not done its job.

    `tools_seen` comes from the collector's counter rather than from the
    trace steps. Reading the steps would report every tool missing under
    `trace_level="off"`, which is how "do not print a trace" turned into
    "every run failed" once already.

    A fact, not a judgement - which is why it is here and not in the
    model-judged half. Either the call happened or it did not.
    """
    issues = []
    for name in must_call:
        if name in tools_seen:
            continue
        issues.append(
            SteeringIssue(
                rule="tools",
                subject=name,
                detail=(
                    f"You have not called {name!r}, and this check cannot be answered "
                    "without it. Call it now, then answer from what it returns. If it "
                    "already failed, say so in `notes` rather than answering around it."
                ),
            )
        )
    return issues


def check_evidence(findings: Sequence[FindingDraft]) -> list[SteeringIssue]:
    """Is the evidence a quote, or the title said twice?

    The test is whether `evidence` adds any word the title did not already
    have. Deliberately lenient: `"content-security-policy" is missing` under
    the title `Missing Content-Security-Policy header` passes, because the
    absence of a header *is* what the tool result shows and there is nothing
    else to quote. What fails is evidence that restates the title and
    nothing more, which is what a model produces when it has no result in
    front of it.
    """
    issues = []
    for draft in findings:
        # Every token, however short: a version number is what makes a
        # quote a quote, and `2.4.29` is three tokens none of which would
        # survive the grounding rule's threshold.
        if tokens(draft.evidence, 1) - tokens(draft.title, 1):
            continue
        issues.append(
            SteeringIssue(
                rule="evidence",
                subject=draft.title,
                detail=(
                    f"The evidence for {draft.title!r} repeats the title and adds "
                    "nothing. Quote the tool result instead - the field and the value "
                    "it returned, as it returned them."
                ),
            )
        )
    return issues


# --------------------------------------------------------------------------
# One pass over an answer
# --------------------------------------------------------------------------


def review(
    output: CheckOutput,
    check: Check,
    corpus: str,
    *,
    tools_seen: set[str] | None = None,
    judged: Sequence[JudgeIssue] = (),
) -> list[SteeringIssue]:
    """Every rule, over one answer. Order is report order, not priority.

    `judged` is appended, never consulted. The judge can add a problem the
    string rules cannot see; it cannot clear one they raised. Written as
    concatenation rather than as a merge so there is no version of this
    function where a lenient judging call lets an ungrounded finding
    through - the property is in the shape of the code, not in a comment
    asking the next reader to preserve it.
    """
    deterministic = [
        *check_tools_used(tools_seen or set(), check.must_call),
        *check_coverage(output, check.required_coverage),
        *check_grounding(output.findings, corpus),
        *check_evidence(output.findings),
    ]
    return [*deterministic, *(_from_judge(issue) for issue in judged)]


def _from_judge(issue: JudgeIssue) -> SteeringIssue:
    """One judge verdict as a steering issue.

    The rule is prefixed so a reader of the trace can tell which half of
    steering spoke. A `judge:follows` step that turns out to be wrong is a
    different conversation from a `grounding` step that does.
    """
    return SteeringIssue(
        rule=f"judge:{issue.rule}",
        subject=issue.subject,
        detail=issue.detail,
    )


def message_for(issues: Sequence[SteeringIssue]) -> str:
    """The turn sent back to the model.

    One message for every issue rather than one per round: each round costs
    a model call and a turn from the check's budget, and a model that fixes
    one problem per round runs out of budget before it runs out of problems.

    It restates the structured-output contract at the end because a model
    asked to revise tends to answer in prose about what it changed.
    """
    lines = [
        "Your answer does not satisfy this check's rules yet. Fix each point "
        "below and answer again in full.",
        "",
    ]
    for issue in issues:
        lines.append(f"- [{issue.rule}] {issue.detail}")
    lines += [
        "",
        "Answer with the complete structured output again - every finding you "
        "are keeping, not only the ones you changed. Do not add a finding you "
        "cannot quote a tool result for.",
        "",
        "Change only what the points above require. Every other field keeps the "
        "value you already gave it - severities especially. You judged those "
        "against the skill with the tool result in front of you, and nothing "
        "above is a reason to revisit them.",
    ]
    return "\n".join(lines)
