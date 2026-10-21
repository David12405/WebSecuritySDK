@echo off
REM Executable entry point for WEBSEC_WHATWEB_PATH.
REM
REM `whatweb.py` calls the configured path with create_subprocess_exec, which
REM needs something Windows can execute directly. A .ps1 is not; this .cmd is.
REM All it does is hand the arguments to the shim that does the real work.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0whatweb.ps1" %*
exit /b %ERRORLEVEL%
