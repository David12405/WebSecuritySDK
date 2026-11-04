"""The `cors` check.

The probe sends an origin no site should be configured to trust. A target
that echoes it back trusts whoever asks, which is the finding this check
exists to catch - and `allow_origin: null`, meaning no CORS headers at all,
is the secure default rather than a gap.
"""

from __future__ import annotations

from .base import Check, register

CORS = register(
    Check(
        name="cors",
        task=(
            "Examine what the target is willing to share cross-origin. Call "
            "get_cors_policy exactly once, then answer from what it returned.\n\n"
            "The probe claims to be an origin the site has no reason to trust. "
            "Report a finding if that origin is echoed back, if credentials are "
            "allowed alongside a permissive origin, or if a shared cache could serve "
            "one origin's response to another. No CORS headers at all is the secure "
            "default - say so and report nothing. CORS governs what a page may "
            "*read*, never what it may request; phrase findings that way.\n\n"
            "Name allow_origin and allow_credentials in `notes`, with the values the "
            "probe returned for them, including when both are absent. 'No CORS "
            "headers were present' does not say which two you checked for."
        ),
        tools=("get_cors_policy",),
        required_coverage={
            "allow-origin": ["allow_origin", "access-control-allow-origin", "allowed origin"],
            "allow-credentials": [
                "allow_credentials",
                "access-control-allow-credentials",
                "credentials",
            ],
        },
    )
)
