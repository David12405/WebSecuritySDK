"""WebSecurityCheck SDK - public surface.

Only two names are public: the entry point and the result types. Everything
else in this package is internal and may change without notice.

    from websecuritycheck import SecurityChecker

    checker = SecurityChecker(model="...", scope=["https://myapp.com"])
    result = checker.check_headers(target="https://myapp.com")

INIT: exports only. Re-export SecurityChecker, CheckResult, Finding, ErrorInfo
once those modules carry an implementation.
"""

#: Reported in every SARIF export, so a report says which SDK produced it.
#: Kept in step with `version` in pyproject.toml.
__version__ = "0.1.0"
