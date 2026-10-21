# scripts/

Environment setup for the two Layer 6 tools that need something outside
Python. Nothing here is part of the SDK - the runner already exists
(`examples/probe_target.py`), and these only make it possible to run.

| Tool | Needs | Script |
|---|---|---|
| `fingerprint_web` | the `whatweb` binary | `whatweb.cmd` + `whatweb.ps1` |
| `crawl_web`, `passive_web_analysis` | a running ZAP daemon | `zap-up.ps1` |

The other eight tools need neither and run today.

## WhatWeb

WhatWeb is Ruby and has no Windows build, so it runs in WSL and the shim
translates the one path that has to cross the boundary.

```powershell
wsl -d Ubuntu-24.04 -- sudo apt-get update
wsl -d Ubuntu-24.04 -- sudo apt-get install -y whatweb
```

Then put the shim path in `.env`, once:

```
WEBSEC_WHATWEB_PATH=D:\path\to\WebSecuritySDK\scripts\whatweb.cmd
```

and both of these run with nothing set in the shell:

```powershell
python examples/run_check.py https://example.com --check fingerprint
python examples/probe_target.py https://example.com --tool fingerprint_web
```

`.env` rather than the shell because the two entry points read the value by
different routes. `probe_target.py` calls the tool in-process, so anything in
the environment reaches it. `run_check.py` goes through the SDK, which starts
the MCP server as a child process - and that child inherits a fixed list of
variables with no `WEBSEC_*` on it. `config/servers.yaml` closes the gap by
passing the value explicitly, reading `${WEBSEC_WHATWEB_PATH}` from whatever
loaded `.env`. Export it in the shell instead and the direct call works while
the SDK reports `E_TOOL_UNAVAILABLE`.

`whatweb.py` writes `--log-json` to a Windows temp path and reads the file
back afterwards. WSL cannot see a Windows path as written, so the shim runs
it through `wslpath`. Skip that and WhatWeb writes somewhere inside the
distro, exits 0, and the caller reports `E_PARSE: WhatWeb did not produce
JSON output` - which is true, and says nothing about why.

## ZAP

```powershell
.\scripts\zap-up.ps1 -WithJuiceShop

$env:WEBSEC_ZAP_BASE_URL = "http://127.0.0.1:8080"
$env:WEBSEC_ZAP_API_KEY  = "websec-local-dev"
python examples/probe_target.py http://websec-juice-shop:3000 --tool crawl_web

.\scripts\zap-up.ps1 -Down
```

Needs Docker Desktop running.

### The ZAP spider is active traffic

`get_response_headers` sends one request. The ZAP spider crawls: it follows
every link it finds and can submit forms, which is hundreds of requests and
writes to whatever the forms write to.

ARCHITECTURE.md section 4.4 currently permits passive probes only, and
whether these two tools fall inside it is an open question for the mentor.
Until it is answered, run them against a target you control.

`-WithJuiceShop` starts one: OWASP Juice Shop, a deliberately vulnerable app,
on a Docker network ZAP shares. The crawl reaches the app by container name
rather than through the host, so it cannot wander into anything else running
on the machine.

## Not covered here

`nmap` also needs a binary, and it is active scanning by any reading - a port
scan is not something a browser does. It is left out until section 4.4 is
settled rather than made convenient first.
