"""Pure deterministic browser exploration rules, URL canonicalization, and gap recording."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict

from .._urls import normalize_path, origin_identity, same_origin

MAX_GAPS = 50
MAX_TEXT = 2048

_STATIC_ASSET_SUFFIXES = (
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".css",
    ".woff",
    ".woff2",
    ".ttf",
    ".pdf",
    ".zip",
    ".gz",
    ".mp4",
    ".mp3",
)
_IGNORED_LINK_SCHEMES = ("javascript:", "mailto:", "tel:", "data:", "blob:")
_DENY_TOKENS = frozenset(
    {
        "delete",
        "remove",
        "destroy",
        "drop",
        "reset",
        "clear",
        "logout",
        "signout",
        "login",
        "signin",
        "register",
        "signup",
        "cart",
        "checkout",
        "pay",
        "purchase",
        "buy",
        "order",
        "save",
        "update",
        "create",
        "edit",
        "upload",
        "transfer",
        "subscribe",
        "unsubscribe",
        "password",
    }
)
_DENY_PHRASES = ("log out", "sign out", "log in", "sign in", "sign up", "add to cart")
_ALLOW_READ_TOKENS = frozenset({"details", "show", "expand", "search", "filter"})


class BrowserReconGap(BaseModel):
    model_config = ConfigDict(extra="forbid")
    gap_id: str
    url: str
    reason: str
    status: str
    element: str | None = None
    detail: str | None = None


def url_origin(url: str) -> tuple[str, str, int]:
    identity = origin_identity(url)
    if identity is not None:
        return identity
    parsed = urlsplit(url)
    return (
        parsed.scheme.lower(),
        (parsed.hostname or "").rstrip(".").lower(),
        parsed.port or (443 if parsed.scheme.lower() == "https" else 80),
    )


def spa_route_fragment(fragment: str) -> str:
    return fragment if fragment.startswith(("/", "!/")) else ""


def canonical_url_key(url: str) -> str:
    parsed = urlsplit(url)
    scheme, host, port = url_origin(url)
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    host_part = f"[{host}]" if ":" in host and not host.startswith("[") else host
    netloc = host_part if default_port else f"{host_part}:{port}"
    query_pairs = sorted(parse_qsl(parsed.query, keep_blank_values=True))
    query = urlencode(query_pairs)
    fragment = spa_route_fragment(parsed.fragment)
    return urlunsplit((scheme, netloc, normalize_path(parsed.path), query, fragment))


def query_signature_key(
    url: str,
) -> tuple[tuple[str, str, int], str, tuple[str, ...], str]:
    parsed = urlsplit(url)
    param_names = tuple(
        sorted({name for name, _value in parse_qsl(parsed.query, keep_blank_values=True) if name})
    )
    return (
        url_origin(url),
        normalize_path(parsed.path),
        param_names,
        spa_route_fragment(parsed.fragment),
    )


def is_excluded(url: str, excluded_scope: list[str]) -> bool:
    if not excluded_scope:
        return False
    parsed = urlsplit(url)
    url_path = normalize_path(parsed.path)
    url_host = (parsed.hostname or "").rstrip(".").lower()
    target_origin = url_origin(url)
    for entry in excluded_scope:
        raw = str(entry).strip()
        if not raw:
            continue
        if raw.startswith("/"):
            norm_entry = normalize_path(raw).rstrip("/") or "/"
            if norm_entry == "/" or url_path == norm_entry or url_path.startswith(norm_entry + "/"):
                return True
        elif "://" in raw:
            if url_origin(raw) != target_origin:
                continue
            entry_path = normalize_path(urlsplit(raw).path).rstrip("/") or "/"
            if entry_path == "/" or url_path == entry_path or url_path.startswith(entry_path + "/"):
                return True
        elif url_host == raw.rstrip(".").lower():
            return True
    return False


def text_tokens(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", text.casefold()))


def is_navigable_link(url: str, raw_href: str, target: str, excluded_scope: list[str]) -> bool:
    stripped = raw_href.strip()
    if not stripped or (stripped.startswith("#") and not spa_route_fragment(stripped[1:])):
        return False
    lowered = stripped.lower()
    if lowered.startswith(_IGNORED_LINK_SCHEMES):
        return False
    if not same_origin(target, url) or is_excluded(url, excluded_scope):
        return False
    parsed = urlsplit(url)
    path_lower = parsed.path.lower()
    if any(path_lower.endswith(suffix) for suffix in _STATIC_ASSET_SUFFIXES):
        return False
    tokens = text_tokens(f"{parsed.path} {raw_href}")
    return not bool(tokens & {"logout", "signout"})


def classify_interactive_element(element: dict[str, Any]) -> tuple[str, str]:
    """Conservatively classify an interactive DOM element.

    Returns `(disposition, detail_code)` where `disposition` is one of
    `"allow_disclosure"`, `"allow_read"`, `"deny"`, `"skip_workflow"`, `"unclassified"`.
    """
    haystack = " ".join(
        str(element.get(key) or "")
        for key in ("id", "name", "class_name", "text", "aria_label", "href", "form_action")
    ).casefold()
    tokens = text_tokens(haystack)
    if (tokens & _DENY_TOKENS) or any(phrase in haystack for phrase in _DENY_PHRASES):
        return "deny", "unsafe_interaction_skipped"

    if element.get("in_non_get_form"):
        return "skip_workflow", "workflow_input_required"

    tag = str(element.get("tag") or "").lower()
    role = str(element.get("role") or "").lower()
    aria_expanded = str(element.get("aria_expanded") or "").lower()
    aria_controls = str(element.get("aria_controls") or "").strip()
    aria_haspopup = str(element.get("aria_haspopup") or "").lower()

    if tag == "summary" or role == "tab":
        return "allow_disclosure", "disclosure"

    # Never treat role="menuitem" as safe by default; only permit explicit submenu disclosure.
    if role == "menuitem":
        if aria_expanded == "false" and (aria_controls or aria_haspopup in {"menu", "true"}):
            return "allow_disclosure", "disclosure"
        return "unclassified", "unclassified_interactive_elements"

    if aria_expanded == "false":
        return "allow_disclosure", "disclosure"

    elem_type = str(element.get("type") or "").lower()
    form_method = str(element.get("form_method") or "").upper()
    is_button_or_get_submit = (
        (tag == "button" and elem_type == "button")
        or (tag == "input" and elem_type == "button")
        or (form_method == "GET" and tag in {"button", "input"})
    )
    if not is_button_or_get_submit:
        return "unclassified", "unclassified_interactive_elements"

    read_haystack = " ".join(
        str(element.get(key) or "") for key in ("id", "name", "text", "aria_label")
    ).casefold()
    read_tokens = text_tokens(read_haystack)
    if (read_tokens & _ALLOW_READ_TOKENS) or "view details" in read_haystack:
        if element.get("container_has_empty_required_input"):
            return "skip_workflow", "workflow_input_required"
        return "allow_read", "read_trigger"

    return "unclassified", "unclassified_interactive_elements"


class GapRecorder:
    """Bounded, deduplicated collector for browser Recon Gaps."""

    def __init__(self, warnings: list[str], max_gaps: int = MAX_GAPS) -> None:
        self._warnings = warnings
        self._max_gaps = max_gaps
        self._seen: set[tuple[str, str]] = set()
        self.gaps: list[BrowserReconGap] = []

    def add(
        self,
        *,
        url: str,
        reason: str,
        status: str,
        dedup_key: str,
        element: str | None = None,
        detail: str | None = None,
    ) -> None:
        if len(self.gaps) >= self._max_gaps:
            return
        composite = (reason, dedup_key)
        if composite in self._seen:
            return
        self._seen.add(composite)
        gap = BrowserReconGap(
            gap_id=f"GAP-{len(self.gaps) + 1:03d}",
            url=url,
            reason=reason,
            status=status,
            element=element[:MAX_TEXT] if element else None,
            detail=detail[:MAX_TEXT] if detail else None,
        )
        self.gaps.append(gap)
        self._warnings.append(
            f"recon_gap:{gap.reason}:{gap.status} url={gap.url} element={gap.element or '-'}"
        )


def normalize_form_entry(raw: dict[str, Any], current_page_url: str) -> dict[str, Any]:
    raw_action = raw.get("action")
    action_url = urljoin(current_page_url, str(raw_action)) if raw_action else current_page_url
    return {
        "page_url": str(raw.get("page_url") or current_page_url),
        "action": action_url,
        "method": str(raw.get("method") or "GET").upper(),
        "enctype": raw.get("enctype"),
        "controls": list(raw.get("controls") or [])[:100],
    }


def form_dedup_key(form: dict[str, Any]) -> tuple[str, str, str, tuple[str, ...]]:
    control_names = tuple(
        str(ctrl.get("name") or "")
        for ctrl in form.get("controls") or []
        if isinstance(ctrl, dict) and ctrl.get("name")
    )
    return (
        str(form.get("action") or ""),
        str(form.get("method") or "GET").upper(),
        str(form.get("enctype") or ""),
        control_names,
    )

