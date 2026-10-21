"""MCP client, per-check allowlist, dead-server handling.

Much thinner than it was going to be. Strands ships `MCPClient`, including
transport detection, a startup timeout and load-time tool filters, so what
is left here is the part that is ours: reading `config/servers.yaml`,
handing each check only the tools it declares, and turning a server that
does not come up into an `errors[]` entry instead of a traceback.

**The filter is not the rule.** `tool_filters` decides which tools the model
is *shown*; the scope guard decides which calls may *run*. They are not
interchangeable - a filter never looks at a target, and the guard has to
hold even for a tool that reached the agent some other way. Both, always.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from contextlib import ExitStack
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from strands.tools.mcp import MCPClient
from strands.tools.mcp.mcp_client import ToolFilters

from ..results.models import ErrorInfo

DEFAULT_STARTUP_TIMEOUT_S = 30


@dataclass(frozen=True)
class ServerSpec:
    """One entry of `config/servers.yaml`, after validation."""

    name: str
    command: str
    args: tuple[str, ...] = ()
    cwd: str | None = None
    env: dict[str, str] = field(default_factory=dict)
    startup_timeout_s: int = DEFAULT_STARTUP_TIMEOUT_S


def load_server_specs(path: str | Path) -> list[ServerSpec]:
    """Read the enabled stdio servers out of `servers.yaml`.

    Only stdio for now. An HTTP server is a config shape Strands already
    supports, but nobody has one to point at yet, and a code path with no
    server behind it is a code path nobody has run.
    """
    document = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    specs: list[ServerSpec] = []
    for entry in document.get("servers") or []:
        if not entry.get("enabled", True):
            continue
        if entry.get("transport", "stdio") != "stdio":
            raise ValueError(
                f"server {entry.get('name')!r}: only the stdio transport is supported today"
            )
        specs.append(
            ServerSpec(
                name=entry["name"],
                command=entry["command"],
                args=tuple(entry.get("args") or ()),
                cwd=entry.get("cwd"),
                env=dict(entry.get("env") or {}),
                startup_timeout_s=int(entry.get("startup_timeout_s", DEFAULT_STARTUP_TIMEOUT_S)),
            )
        )
    return specs


def _mcp_servers_config(specs: Iterable[ServerSpec]) -> dict[str, Any]:
    """Our YAML in the `mcpServers` shape Strands reads."""
    return {
        spec.name: {
            "command": spec.command,
            "args": list(spec.args),
            **({"cwd": spec.cwd} if spec.cwd else {}),
            **({"env": spec.env} if spec.env else {}),
        }
        for spec in specs
    }


@dataclass
class ToolProvider:
    """Starts the servers a run needs and hands out one check's tools.

    Use it as a context manager: the servers are subprocesses, and a run
    that raises part-way must not leave them behind.

        with ToolProvider(specs) as provider:
            tools = provider.tools_for(["get_response_headers"])
            ...
        # every server stopped here, however the block ended
    """

    specs: Sequence[ServerSpec]
    errors: list[ErrorInfo] = field(default_factory=list)
    clients: list[MCPClient] = field(default_factory=list)
    _stack: ExitStack = field(default_factory=ExitStack, repr=False)

    def __enter__(self) -> ToolProvider:
        config = _mcp_servers_config(self.specs)
        try:
            # `continue_on_error` so one unresolvable server entry skips that
            # server rather than ending the run before any tool is tried.
            clients = MCPClient.load_servers(config, continue_on_error=True)
        except Exception as exc:  # a malformed config, not a dead server
            self.errors.append(
                ErrorInfo(
                    kind="tool",
                    code="E_SERVER_UNAVAILABLE",
                    message=f"could not build the MCP server list: {exc}",
                )
            )
            return self

        for client in clients:
            # One dead server does not end the run: the check may not need
            # its tools, and if it does, that surfaces as E_TOOL_MISSING
            # with the tool named, which is the more useful error.
            try:
                self._stack.enter_context(client)
                self.clients.append(client)
            except Exception as exc:
                self.errors.append(
                    ErrorInfo(
                        kind="tool",
                        code="E_SERVER_UNAVAILABLE",
                        message=f"MCP server did not start: {exc}",
                    )
                )
        return self

    def __exit__(self, *exc_info: object) -> None:
        self._stack.close()

    # -- what a check gets ------------------------------------------------

    def available(self) -> dict[str, Any]:
        """Every tool every live server exposes, by name."""
        found: dict[str, Any] = {}
        for client in self.clients:
            for tool in client.list_tools_sync():
                found.setdefault(tool.tool_name, tool)
        return found

    def tools_for(self, allowlist: Sequence[str]) -> list[Any]:
        """The tools one check declares, and an error for each one missing.

        A check asking for a tool no server provides is `E_TOOL_MISSING` and
        terminal: the check cannot do its job, and retrying a tool that does
        not exist will not make it exist.
        """
        found = self.available()
        tools = []
        for name in allowlist:
            if name in found:
                tools.append(found[name])
            else:
                self.errors.append(
                    ErrorInfo(
                        kind="tool",
                        code="E_TOOL_MISSING",
                        tool=name,
                        message=(
                            f"no connected MCP server provides {name!r}; "
                            f"available: {', '.join(sorted(found)) or 'none'}"
                        ),
                    )
                )
        return tools


def filters_for(allowlist: Sequence[str]) -> ToolFilters:
    """Load-time convenience, so the model is not shown tools it may not use.

    Not a substitute for the scope guard - see the module docstring.
    """
    return {"allowed": list(allowlist)}
