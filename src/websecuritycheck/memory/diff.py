"""The run diff - a pure decision, like the scope guard and steering.

    diff_runs(previous, current, tools_ok, check_tools)  ->  RunDiff

Given the findings of the previous run and of this one, decide which are
new, which are unchanged, which were fixed, and which could not be verified.
It touches no database and runs no agent, so it is unit-testable with two
lists of findings and a set of tool names - the same split the rest of the
policy layer keeps.

**Why `fixed` and `unverified` are different.** A finding that was present
last run and is absent now has two possible stories. Either the tool that
would have found it ran again and did not - it was *fixed*. Or that tool
failed this run, so the finding simply could not be re-checked - it is
*unverified*. Collapsing the two reports a broken probe as an improvement,
which is the one reading of a security diff that is actively misleading.

**The honest default is `unverified`.** `fixed` is a claim - "this is gone"
- and a claim needs a warrant: the tool that would re-find it measured
something this run. When a finding names no tool, the warrant is weaker, so
it is only `fixed` if *every* tool the check could have used ran, and
`unverified` otherwise. We would rather under-claim a fix than report one we
cannot stand behind.
"""

from __future__ import annotations

from collections.abc import Sequence

from ..results.models import Finding, RunDiff


def diff_runs(
    previous: Sequence[Finding],
    current: Sequence[Finding],
    *,
    tools_ok: set[str],
    check_tools: Sequence[str],
    previous_run_id: str | None = None,
) -> RunDiff:
    """Compare two runs of one check on one target.

    `tools_ok` is the set of tools that measured something this run - the
    collector's `tools_seen`, not the trace steps, so a filtered trace does
    not make every fix look unverified. `check_tools` is what the check could
    have called, used only to judge a finding that named no tool of its own.
    """
    previous_by_id = {f.id: f for f in previous}
    current_ids = {f.id for f in current}

    new = sorted(current_ids - previous_by_id.keys())
    unchanged = sorted(current_ids & previous_by_id.keys())

    fixed: list[str] = []
    unverified: list[str] = []
    for finding_id, finding in previous_by_id.items():
        if finding_id in current_ids:
            continue  # still here - counted as unchanged above
        if _was_rechecked(finding, tools_ok, check_tools):
            fixed.append(finding_id)
        else:
            unverified.append(finding_id)

    # Every id in any bucket, with its title. `previous` covers fixed and
    # unverified - whose findings are gone from this run's result - and
    # `current` covers new and unchanged, so the two together name them all.
    labels = {f.id: f.title for f in previous}
    labels.update({f.id: f.title for f in current})

    return RunDiff(
        previous_run_id=previous_run_id,
        new=new,
        fixed=sorted(fixed),
        unchanged=unchanged,
        unverified=sorted(unverified),
        labels=labels,
    )


def next_open_findings(
    open_before: Sequence[Finding],
    current: Sequence[Finding],
    *,
    tools_ok: set[str],
    check_tools: Sequence[str],
) -> list[Finding]:
    """The open-findings ledger after this run.

    A finding is *open* while it is either present or unverified - a known
    problem we have not confirmed gone. This is what the next run diffs
    against, in place of "the last run's reported findings", so a finding that
    went unverified is carried forward run after run until a successful
    re-measurement settles it, instead of silently dropping out the moment a
    later baseline no longer lists it.

    The rule mirrors `diff_runs` exactly, which is the point:

    - reported this run        -> present, kept (reconfirmed or new)
    - gone, its tool ran OK    -> fixed, dropped from the ledger
    - gone, its tool did not   -> unverified, carried forward

    `fixed` is the only way out of the ledger, and it needs the same warrant
    `diff_runs` demands: a tool that would have re-found it actually measured.
    """
    current_ids = {f.id for f in current}
    ledger: list[Finding] = list(current)
    for finding in open_before:
        if finding.id in current_ids:
            continue  # reported again this run - already carried as present
        if not _was_rechecked(finding, tools_ok, check_tools):
            ledger.append(finding)  # unverified: still open, carry it
    return ledger


def _was_rechecked(finding: Finding, tools_ok: set[str], check_tools: Sequence[str]) -> bool:
    """Did the tool that would re-find this gone finding actually run?

    A finding that names its source tool is re-checked exactly when that tool
    ran successfully. A finding that names none could have come from any of
    the check's tools, so we can only call it re-checked when all of them
    ran - anything less leaves a tool that might have found it unaccounted
    for, and an unaccounted-for tool is the definition of `unverified`.
    """
    if finding.source_tool:
        return finding.source_tool in tools_ok
    return bool(check_tools) and all(tool in tools_ok for tool in check_tools)
