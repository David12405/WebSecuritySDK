"""LAYER 1 - the public API.  Step 1 of the turn diagram.

    check_headers(target) -> CheckResult

One typed method per check. The method validates its parameters and the
target against `Settings.scope` *before* an agent exists, so an out-of-scope
call never reaches a model or a tool. It then hands the matching `Check`
definition to `engine.runner` (step 2) and returns the `CheckResult` the run
produced (step 7).

The developer never writes a prompt and never imports `strands`.

INIT: no implementation yet.
"""
