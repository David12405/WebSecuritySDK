"""Run lifecycle hooks.  Steps 3 and 7 of the turn diagram.

BeforeInvocation (step 3)
    open the trace, and let `memory.target_store` pin the previous run's
    summary into working memory so this run can be diffed against it.

AfterInvocation (step 7)
    save findings, errors and the tool log to the TargetStore, compute the
    diff against the previous run, close the trace, and hand back the
    `CheckResult`.

INIT: no implementation yet.
"""
