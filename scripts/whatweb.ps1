# WhatWeb shim: runs the Linux binary in WSL on behalf of a Windows caller.
#
# WhatWeb is a Ruby tool with no Windows build. Ubuntu-24.04 has it in apt, so
# the binary is one `wsl` hop away - the only real work is the filesystem.
# `whatweb.py` builds `--log-json=<a Windows temp path>` and then reads that
# file back from Windows, so the path handed to WSL has to point at the same
# bytes. `wslpath` does the translation; without it WhatWeb writes to a
# Linux-side path that exists only inside the distro, exits 0, and the caller
# fails with "WhatWeb did not produce JSON output" - a confusing way to be
# told the two sides disagreed about where the file went.
#
# Point the tool at this shim:
#   $env:WEBSEC_WHATWEB_PATH = "d:\Internship\WebSecuritySDK\scripts\whatweb.cmd"
#
# Install the binary first:
#   wsl -d Ubuntu-24.04 -- sudo apt-get update
#   wsl -d Ubuntu-24.04 -- sudo apt-get install -y whatweb

$ErrorActionPreference = "Stop"

$distro = if ($env:WEBSEC_WSL_DISTRO) { $env:WEBSEC_WSL_DISTRO } else { "Ubuntu-24.04" }

# `-e` rather than `--`. Both run a binary without a login shell, but `--`
# sends the arguments through a layer that treats a backslash as an escape,
# so `C:\Users\huuda\...` arrives as `C:UsershuudaAppData...` - a path that
# is not absolute, is not a file, and produces a wslpath error mentioning a
# path nobody wrote. `-e` hands the arguments to execvp untouched. Measured,
# not assumed: `--` fails on this machine and `-e` does not.
$WSL_EXEC = "-e"

# Rewrite only the value of --log-json. Every other argument is a flag or the
# target URL, and a URL run through wslpath comes back mangled.
$translated = foreach ($arg in $args) {
    if ($arg -like "--log-json=*") {
        $winPath = $arg.Substring("--log-json=".Length)
        $linuxPath = & wsl.exe -d $distro $WSL_EXEC wslpath -a "$winPath" 2>$null
        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($linuxPath)) {
            Write-Error "wslpath could not translate $winPath"
            exit 1
        }
        "--log-json=$($linuxPath.Trim())"
    }
    else {
        $arg
    }
}

& wsl.exe -d $distro $WSL_EXEC whatweb @translated
exit $LASTEXITCODE
