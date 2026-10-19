"""Hard rule - AfterToolCall.  Tool output is untrusted data.

Everything a tool returns is wrapped and labelled as target-derived data
before the model sees it, and trimmed to a size cap. Nothing inside it can
change the prompt, the skill or the allowlist. The full output goes to the
context store; the model pulls detail back only when it needs to quote it.

INIT: no implementation yet.
"""
