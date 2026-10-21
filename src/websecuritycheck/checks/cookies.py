"""The `cookies` check.

A response that sets no cookies is a real answer, not a failure. The skill
says to report that in `notes` and return nothing - which lands as `passed`,
correctly, because a tool did run and did measure.
"""

from __future__ import annotations

from .base import Check, register

COOKIES = register(
    Check(
        name="cookies",
        task=(
            "Examine the cookies the target sets and report which of them are not "
            "protected. Call get_cookies exactly once, then answer from what it "
            "returned.\n\n"
            "For each cookie, judge Secure, HttpOnly and SameSite, and weigh the "
            "result by what that cookie plainly is: a missing flag on a session or "
            "auth cookie is a different finding from the same flag missing on an "
            "analytics cookie. Never quote or reconstruct a cookie value - the probe "
            "returns only its length, deliberately."
        ),
        tools=("get_cookies",),
        required_coverage={
            # These topics *are* the attribute names the tool returns, so
            # they need few aliases - the lesson from `tls` is that concepts
            # need them and field names do not.
            "secure": [],
            "httponly": ["http-only", "http only"],
            "samesite": ["same-site", "same site"],
        },
    )
)
