"""The `surface` check.  **Parked - not in the default scan.**

The first *multi-step* check, and the reason the harness exists at all. The
four default checks each call one tool and answer; this one calls several,
and each call is chosen from what the last returned - fingerprint what runs,
crawl the origin, probe the endpoints crawl found, reach for the browser when
the page is JavaScript, parse an API spec if one turns up. That branching is
the thing a script cannot do and an agent can: the second step is not knowable
before the first has run.

It owns `fingerprint_web`, `crawl_web`, `probe_http`, `explore_browser` and
`parse_api_spec`. `probe_http` is the HTTP workhorse: it reads the same
response headers `get_response_headers` does, but for an endpoint crawl
discovered rather than for the root alone. `fingerprint_web` (WhatWeb) is what
populates `TargetModel.technologies` - it was the standalone `fingerprint`
check, but fingerprinting is reconnaissance, not a verdict of its own, so it
belongs to the step that maps the surface rather than to a check that had to
invent findings to justify running.

**Recon is a map, not a verdict.** Most of what this check finds is inventory
- which technologies run, which endpoints exist - and inventory belongs in
`notes`. A finding needs a genuine exposure quoted from a tool result: an
endpoint reachable that should not be, a dangerous method allowed, software
disclosed in a header, an API spec served to the public. The lesson is the
old `fingerprint` check's: a recon step pushed to produce findings invents
them, and the ones it invented all rested on the page title, which is a string
the target chooses.

**No tool is required.** `required_tools=()` because the tools degrade
independently - `fingerprint_web` needs WhatWeb, `crawl_web` needs ZAP,
`explore_browser` needs Chromium - and a surface map built from `probe_http`
alone is still a real answer. A missing tool is `E_TOOL_UNAVAILABLE` in
`notes`, not a failed check.

Parked (`in_default_scan=False`): its shape is still being argued, and a
scan of a site should not silently fan out into a crawl. Run it by name:

    python examples/run_check.py <url> --check surface --target-store recon.db
"""

from __future__ import annotations

from .base import Check, register

SURFACE = register(
    Check(
        name="surface",
        task=(
            "Map the reachable surface of the target and report what it exposes. "
            "This is reconnaissance: the answer is mostly a map, not a list of "
            "defects.\n\n"
            "Work in steps, and let each step decide the next:\n"
            "1. Call fingerprint_web on the target to learn what technology runs "
            "there. Read the detected components from each entry's name, never "
            "from page text. Do not claim a version is vulnerable or outdated - "
            "the disclosure of a version is the point, not a CVE you cannot see.\n"
            "2. Call crawl_web on the target to list its endpoints. If it is "
            "unavailable, say so in notes and work from what you can reach.\n"
            "3. For the endpoints worth a closer look, call probe_http to see the "
            "method, the response headers, and whether it answers without "
            "authentication. Probe only targets inside the scope you were given.\n"
            "4. If the page is JavaScript and crawl found little, call "
            "explore_browser on the target to surface endpoints the script calls.\n"
            "5. If, and only if, you found a served API specification (an "
            "openapi.json, swagger.json or similar), call parse_api_spec on it. "
            "Never call it on a page, a script, a stylesheet or an image.\n\n"
            "Call each tool only when its step's condition is met. A tool call "
            "that fails is recorded as an error on this run, so do not retry a "
            "tool that already failed, and do not fire one on the wrong input.\n\n"
            "Put the map in `notes`: the technologies fingerprint_web named and "
            "the endpoints you found. Report a finding only for a genuine exposure "
            "you can quote: an endpoint reachable that should not be without "
            "authentication, a dangerous method allowed, software and version "
            "disclosed, or an API spec served to anyone. Do not turn the inventory "
            "into findings, and do not report an endpoint merely for existing."
        ),
        tools=("fingerprint_web", "crawl_web", "probe_http", "explore_browser", "parse_api_spec"),
        # None is required: the tools degrade independently and a map built
        # from probe_http alone is still an answer. See the module docstring.
        required_tools=(),
        required_coverage={
            # Both are concepts, not tool field names - a surface map is
            # phrased many ways. The aliases are how a model tends to write
            # the two things this check must address.
            "endpoints": ["endpoint", "url", "path", "route", "reachable"],
            "technologies": ["technology", "server", "x-powered-by", "stack", "software"],
        },
        # A crawl is several model turns of tool calls and reasoning, not the
        # one turn a single-probe check needs.
        max_turns=15,
        in_default_scan=False,  # see the module docstring
    )
)
