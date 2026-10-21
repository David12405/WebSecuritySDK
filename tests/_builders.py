"""Builders shared by the test modules.

Not `conftest.py`: these are plain callables used inside `parametrize` and at
module level, which fixtures cannot be. `tests/` is not a package, so pytest
puts this directory on `sys.path` and the import below works as written.
"""

from __future__ import annotations

from websecuritycheck.results import Finding, FindingDraft, TraceStep


def draft(
    title: str = "CSP header missing",
    location: str = "Content-Security-Policy",
    **kw,
) -> FindingDraft:
    return FindingDraft(
        title=title,
        severity=kw.pop("severity", "high"),
        location=location,
        evidence=kw.pop("evidence", "Response headers contained no Content-Security-Policy."),
        **kw,
    )


def tool_step(step_id: str = "s1", name: str = "get_response_headers", **kw) -> TraceStep:
    kw.setdefault("summary", "200, 12 headers")
    return TraceStep(id=step_id, kind="tool_call", name=name, **kw)


def finding(check: str = "headers", **kw) -> Finding:
    return Finding.from_draft(draft(**kw), check, ["s1"])
