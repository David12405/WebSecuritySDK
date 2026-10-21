"""The `fingerprint` check.  **Parked - not in the default scan.**

The first check whose tool is not an HTTP probe. `fingerprint_web` runs the
WhatWeb binary in a subprocess, which changes nothing about how the check is
written - the hooks key on the tool call, not on what is behind it - but it
does mean the check fails differently. WhatWeb absent is
`E_TOOL_UNAVAILABLE`, a fact about this machine rather than about the
target, and the skill says so plainly so the model does not report it as a
property of the site.

## Why it is parked

Written as a check, it does not work, and running it longer would not have
fixed it. Measured over three identical runs against one target it produced
a different answer each time - `HIGH "Exposed admin interface"`, then the
correct two findings, then `MEDIUM "Development component exposed"` - and
the wrong ones all rested on `Title`, which is whatever string the site put
in its title tag. The target was deciding its own severity.

The rule against that was stated three times, in the skill, in the
not-findings table, and in this task. Compliance at a rate is fine for a
suggestion and useless for a boundary, and "a finding rests on a
measurement" is the boundary this SDK exists to hold.

## What it should be instead

Fingerprinting is reconnaissance, and reconnaissance is not a verdict. The
two findings that *were* stable - `Server: Apache/2.4.29` and
`X-Powered-By: PHP/7.2.24` - are response headers, so they belong to the
`headers` check, which already reads headers. What is left over is "what is
running here", which is an input to deciding what to check next rather than
something wrong with the site.

So the shape to build is a recon step that returns an inventory and no
findings, feeding a router that picks the next check. Two things are
undecided and both change the code: whether a recon result is a
`CheckResult` at all when it can never be `passed` or `issues_found`, and
whether the routing is a table in our code or a choice the model makes. The
second is the one that matters - a table is testable, a choice is what the
three runs above already showed.

Kept registered so it stays covered by the suite and runnable by name:

    python examples/run_check.py <url> --check fingerprint
"""

from __future__ import annotations

from .base import Check, register

FINGERPRINT = register(
    Check(
        name="fingerprint",
        task=(
            "Find out what the target publishes about its own technology stack and "
            "report what that hands an attacker. Call fingerprint_web exactly once, "
            "then answer from what it returned.\n\n"
            "Report a published version number, a component that should not be "
            "reachable without authentication, and a development or debug component "
            "running in production.\n\n"
            "An email address is not a finding. A public site publishes contact "
            "addresses on purpose, and one page does not tell you which address was "
            "meant to be there. List them in `notes` instead. The skill states the "
            "one narrow exception.\n\n"
            "Decide what was detected from the `name` field of each entry, never "
            "from page text. A `Title` reading 'Internal Admin' is a string the site "
            "chose to publish, not evidence that an admin interface is reachable. If "
            "WhatWeb did not name the component, you did not detect the component.\n\n"
            "Do not report that a version is vulnerable, outdated or affected by a "
            "CVE. The tool gave you no evidence for that, and distributions backport "
            "fixes without changing the version string. The disclosure is the finding.\n\n"
            "Then list every technology WhatWeb detected in `notes`, with versions "
            "where it gave one. Most of what this check finds is not a defect, and "
            "the inventory is the answer a reader opened a fingerprint report for."
        ),
        tools=("fingerprint_web",),
        in_default_scan=False,  # see the module docstring
        required_coverage={
            # Both topics are concepts rather than field names - WhatWeb's
            # own fields are plugin names like `HTTPServer`, which vary by
            # target and so cannot be required. The aliases are how a model
            # actually phrases the two questions the skill asks.
            "version_disclosure": [
                "version",
                "versions",
                "discloses",
                "disclosure",
                "server header",
                "x-powered-by",
            ],
            "exposed_components": [
                "component",
                "admin",
                "interface",
                "exposed",
                "reachable",
                "debug",
                "no administrative",
            ],
        },
    )
)
