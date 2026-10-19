# Skill: HTTP security headers

> INIT — structure only. The security method is the partner's to write; the
> format below is the contract `engine/runner.py` loads into the system prompt.

## Scope

What this skill covers, and what it deliberately does not.

## Tools

| Tool | When to call it |
|---|---|
| `get_response_headers` | TODO |

## Method

Ordered steps the agent must follow. One observation per step, each tied to a
tool result.

## Must cover

HSTS · CSP · X-Frame-Options · X-Content-Type-Options

Mirror of `check.required_coverage`. Steering sends the answer back if a topic
here is not addressed, so the two lists have to stay in sync.

## Severity guidance

How to rank a finding for this check, so two runs on the same target agree.

## Reporting rules

- Quote the evidence from a tool result in **this** run. Never from memory.
- A tool failure is an error, never a finding.
- If a tool reports `truncated: true`, say so instead of concluding from a
  partial result.
