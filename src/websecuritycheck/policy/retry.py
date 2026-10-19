"""Hard rule - AfterToolCall.  Transient tool failures.

Classifies an `E_*` code as retryable or terminal, retries the retryable
ones up to a try limit, and records every failure as an `ErrorInfo` either
way. A tool failure is never allowed to become a finding.

INIT: no implementation yet.
"""
