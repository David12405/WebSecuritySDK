"""Finding, ErrorInfo, TraceStep, RunDiff, CheckOutput, CheckResult.

`CheckOutput` is what the *model* returns - findings and notes only.
`CheckResult` is what the *developer* gets - the harness adds status, errors,
diff and trace. Keeping the two apart is what makes "findings and errors
never mix" enforceable rather than advisory.

Status rules:

    findings  errors   status
    none      none     passed         - only if at least one tool ran
    some      none     issues_found
    some      some     partial
    none      some     failed

A run that called no tool is never `passed`: it measured nothing, so an empty
findings list is the absence of evidence, not evidence of absence.

INIT: no implementation yet.
"""
