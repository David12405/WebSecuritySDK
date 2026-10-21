# Bring up a ZAP daemon in Docker and print the environment it needs.
#
#   .\scripts\zap-up.ps1            # start, wait, print the env vars
#   .\scripts\zap-up.ps1 -Down      # stop and remove the container
#
# `zap.py` talks to ZAP's REST API over HTTP, so a daemon has to exist before
# crawl_web or passive_web_analysis can do anything. Without it the tool
# raises E_TOOL_UNAVAILABLE ("ZAP base URL is not configured"), which is the
# correct error and tells you nothing about how to fix it.
#
# NOTE ON WHAT THIS ENABLES. The ZAP spider is not a passive probe. It
# crawls the target, follows every link it finds, and can submit forms -
# hundreds of requests where `get_response_headers` makes one. That is
# active traffic, and ARCHITECTURE.md section 4.4 has not yet been settled on
# whether this SDK is allowed to send it. Until the mentor answers, point
# this at a target you control. See `-WithJuiceShop` below for one.

[CmdletBinding()]
param(
    [switch]$Down,
    [switch]$WithJuiceShop,
    [string]$ApiKey = "websec-local-dev",
    [int]$Port = 8080
)

$ErrorActionPreference = "Stop"

# Several docker calls below are expected to fail: `rm -f` on a container that
# was never created, `network create` on one that already exists. Both are the
# idempotent form of "make sure this is gone / present", and their exit codes
# are checked where they matter. With ErrorActionPreference=Stop, a shell that
# has this preference on turns those into terminating errors and the script
# dies on its first clean run. It is off by default today, so this pins the
# behaviour the script was written against rather than inheriting it.
$PSNativeCommandUseErrorActionPreference = $false

$container = "websec-zap"
$juiceShop = "websec-juice-shop"

function Assert-Docker {
    docker info --format '{{.ServerVersion}}' 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Error "The Docker daemon is not reachable. Start Docker Desktop and retry."
        exit 1
    }
}

if ($Down) {
    foreach ($name in @($container, $juiceShop)) {
        docker rm -f $name 2>&1 | Out-Null
    }
    Write-Host "Stopped and removed: $container, $juiceShop"
    exit 0
}

Assert-Docker

if ($WithJuiceShop) {
    # A deliberately vulnerable app, so an active crawl has somewhere legal to
    # go. ZAP reaches it by container name over a shared network rather than
    # through the host, which keeps the crawl off anything else you are running.
    docker network create websec-net 2>&1 | Out-Null
    docker rm -f $juiceShop 2>&1 | Out-Null
    docker run -d --name $juiceShop --network websec-net -p 3000:3000 `
        bkimminich/juice-shop | Out-Null
    Write-Host "Juice Shop starting on http://localhost:3000"
    Write-Host "ZAP reaches it as     http://$juiceShop`:3000"
}

docker rm -f $container 2>&1 | Out-Null
$network = if ($WithJuiceShop) { @("--network", "websec-net") } else { @() }

# api.addrs lets the API answer requests arriving from outside the container.
# Without it ZAP binds the API to loopback *inside* the container and every
# call from Windows comes back 403.
docker run -d --name $container @network -p "$Port`:8080" `
    zaproxy/zap-stable zap.sh -daemon -host 0.0.0.0 -port 8080 `
    -config api.addrs.addr.name=.* `
    -config api.addrs.addr.regex=true `
    -config "api.key=$ApiKey" | Out-Null

$baseUrl = "http://127.0.0.1:$Port"
Write-Host "Waiting for ZAP to answer on $baseUrl ..." -NoNewline

$deadline = (Get-Date).AddSeconds(120)
$ready = $false
while ((Get-Date) -lt $deadline) {
    try {
        $response = Invoke-RestMethod -Uri "$baseUrl/JSON/core/view/version/?apikey=$ApiKey" `
            -TimeoutSec 3
        if ($response.version) { $ready = $true; break }
    }
    catch {
        # Not up yet. ZAP takes 20-40s on a cold start.
    }
    Write-Host "." -NoNewline
    Start-Sleep -Seconds 3
}
Write-Host ""

if (-not $ready) {
    Write-Error "ZAP did not answer within 120s. Check: docker logs $container"
    exit 1
}

Write-Host "ZAP $($response.version) is up."
Write-Host ""
Write-Host "Set these in the shell that runs the tools:"
Write-Host "  `$env:WEBSEC_ZAP_BASE_URL = `"$baseUrl`""
Write-Host "  `$env:WEBSEC_ZAP_API_KEY  = `"$ApiKey`""
Write-Host ""
Write-Host "Then, against a target you control:"
if ($WithJuiceShop) {
    Write-Host "  python examples/probe_target.py http://$juiceShop`:3000 --tool crawl_web"
}
else {
    Write-Host "  python examples/probe_target.py <your-target> --tool crawl_web"
}
Write-Host ""
Write-Host "Stop everything with: .\scripts\zap-up.ps1 -Down"
