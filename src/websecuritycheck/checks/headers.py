"""The `headers` check.

The first check, and the one the whole path was built against. It needs one
tool and asks one question: which response headers that should defend this
site are absent, weak, or saying more than they should.
"""

from __future__ import annotations

from .base import Check, register

HEADERS = register(
    Check(
        name="headers",
        task=(
            "Examine the HTTP response headers of the target and report what is wrong "
            "with them. Call get_response_headers exactly once, then answer from what "
            "it returned.\n\n"
            "Report a finding for every security header that is missing, and for every "
            "one that is present but weak. Also report headers that disclose the "
            "software behind the site. Rank each finding by what it actually exposes "
            "on this target, not by a generic table."
        ),
        tools=("get_response_headers",),
        required_coverage={
            # Topic -> the other ways a model or a tool spells it. The tool's
            # own field names come first, because those are fixed by the
            # contract; the rest is how a model tends to phrase things.
            "strict-transport-security": ["hsts", "strict transport security"],
            "content-security-policy": ["csp", "content security policy"],
            "x-frame-options": ["frame-options", "frame options", "clickjacking"],
            "x-content-type-options": ["content-type-options", "nosniff", "mime sniffing"],
        },
    )
)
