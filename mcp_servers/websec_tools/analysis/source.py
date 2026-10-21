"""Bounded, repository-confined source inspection tools."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict

from ..errors import ToolError, envelope

MAX_TREE_DEPTH = 10
MAX_TREE_FILES = 2_000
MAX_SOURCE_FILE_BYTES = 1_048_576
MAX_READ_LINES = 400
MAX_READ_CHARS = 64 * 1024
MAX_QUERY_LENGTH = 256
MAX_SEARCH_MATCHES = 200
MAX_SNIPPET_CHARS = 500

IGNORED_DIRS = frozenset(
    {
        ".git", ".hg", ".svn", ".venv", "venv", "env", "node_modules",
        "vendor", "dist", "build", "target", "__pycache__", ".pytest_cache",
        ".mypy_cache", ".ruff_cache", "coverage", "htmlcov", ".tox",
    }
)
MANIFEST_NAMES = frozenset(
    {
        "pyproject.toml", "setup.py", "setup.cfg", "requirements.txt", "Pipfile",
        "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
        "go.mod", "Cargo.toml", "Gemfile", "pom.xml", "build.gradle",
        "composer.json", "Dockerfile", "docker-compose.yml", "Makefile",
    }
)
LANGUAGES = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript", ".ts": "typescript",
    ".tsx": "typescript", ".java": "java", ".go": "go", ".rs": "rust", ".rb": "ruby",
    ".php": "php", ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".cs": "csharp",
    ".swift": "swift", ".kt": "kotlin", ".yaml": "yaml", ".yml": "yaml",
    ".json": "json", ".toml": "toml", ".xml": "xml", ".sql": "sql", ".sh": "shell",
    ".html": "html", ".css": "css", ".md": "markdown",
}
SENSITIVE_NAMES = frozenset(
    {
        "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "credentials",
        "credentials.json", "secrets.json",
    }
)
SENSITIVE_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".jks", ".kdb", ".der")


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SourceFileEntry(_Model):
    path: str
    size_bytes: int
    language: str | None = None


class SourceTreeResult(_Model):
    path: str
    files_returned: int
    files: list[SourceFileEntry]
    manifests: list[str]
    languages: dict[str, int]


class SourceFileResult(_Model):
    path: str
    start_line: int
    end_line: int
    total_lines: int
    content: str


class SourceMatch(_Model):
    path: str
    line: int
    column: int
    snippet: str


class SourceSearchResult(_Model):
    path: str
    query: str
    case_sensitive: bool
    files_searched: int
    matches: list[SourceMatch]


def _invalid(code: str, message: str) -> ToolError:
    return ToolError(code, message)


def _validate_root(target: str) -> Path:
    if not isinstance(target, str) or not target or not os.path.isabs(target):
        raise _invalid("E_INVALID_TARGET", "repository target is invalid")
    try:
        root = Path(target).resolve(strict=True)
    except (OSError, RuntimeError):
        raise _invalid("E_INVALID_TARGET", "repository target is invalid") from None
    if not root.is_dir():
        raise _invalid("E_INVALID_TARGET", "repository target is invalid")
    return root


def _resolve_relative(root: Path, value: str, *, reject_symlink: bool = False) -> Path:
    if (
        not isinstance(value, str)
        or not value
        or "\x00" in value
        or any(ord(c) < 32 for c in value)
    ):
        raise _invalid("E_INVALID_ARGUMENT", "path is invalid")
    candidate = Path(value)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise _invalid("E_INVALID_ARGUMENT", "path is invalid")
    raw_path = root / candidate
    if reject_symlink:
        try:
            if raw_path.is_symlink() or any(
                parent.is_symlink() for parent in raw_path.parents if parent != root
            ):
                raise _invalid("E_UNSUPPORTED_INPUT", "symlinked source is not supported")
        except OSError:
            raise _invalid("E_INVALID_ARGUMENT", "path is invalid") from None
    try:
        resolved = raw_path.resolve(strict=True)
    except (OSError, RuntimeError):
        raise _invalid("E_INVALID_ARGUMENT", "path is invalid") from None
    try:
        resolved.relative_to(root)
    except ValueError:
        raise _invalid("E_INVALID_ARGUMENT", "path is outside repository") from None
    return resolved


def relative_path(root: Path, path: Path) -> str:
    rel = path.relative_to(root).as_posix()
    return rel or "."


def is_exposure_safe(path: Path) -> bool:
    name = path.name.lower()
    if name.startswith(".env") or name in SENSITIVE_NAMES:
        return False
    if name.endswith(SENSITIVE_SUFFIXES) or "secret" in name or "password" in name:
        return False
    return True


def is_analyzer_safe(path: Path) -> bool:
    return path.is_file() and not path.is_symlink()


def _iter_files(root: Path, start: Path, *, exposure: bool, max_files: int | None = None):
    count = 0

    def walk(directory: Path):
        nonlocal count
        try:
            entries = sorted(directory.iterdir(), key=lambda item: item.name.casefold())
        except OSError:
            return
        for item in entries:
            if item.is_symlink():
                continue
            if item.is_dir():
                if item.name in IGNORED_DIRS:
                    continue
                yield from walk(item)
            elif item.is_file():
                if exposure and not is_exposure_safe(item):
                    continue
                if max_files is not None and count >= max_files:
                    return
                count += 1
                yield item

    yield from walk(start)


def _read_text(path: Path) -> str:
    try:
        if path.stat().st_size > MAX_SOURCE_FILE_BYTES:
            raise _invalid("E_UNSUPPORTED_INPUT", "source file is too large")
        data = path.read_bytes()
        if b"\x00" in data:
            raise _invalid("E_UNSUPPORTED_INPUT", "binary source is not supported")
        return data.decode("utf-8-sig")
    except ToolError:
        raise
    except (OSError, UnicodeDecodeError):
        raise _invalid("E_UNSUPPORTED_INPUT", "source file is not supported") from None


def _depth(root: Path, path: Path) -> int:
    return len(path.relative_to(root).parts)


def _tree(root: Path, path: str, max_depth: int) -> tuple[dict[str, Any], bool]:
    if (
        not isinstance(max_depth, int)
        or isinstance(max_depth, bool)
        or not 1 <= max_depth <= MAX_TREE_DEPTH
    ):
        raise _invalid("E_INVALID_ARGUMENT", "max_depth is invalid")
    start = _resolve_relative(root, path, reject_symlink=True)
    if not start.is_dir():
        raise _invalid("E_INVALID_ARGUMENT", "path is not a directory")
    files: list[SourceFileEntry] = []
    languages: dict[str, int] = {}
    manifests: list[str] = []
    truncated = False
    candidates: list[Path] = []
    for item in _iter_files(root, start, exposure=True):
        if _depth(root, item) - _depth(root, start) > max_depth:
            truncated = True
            continue
        if len(candidates) >= MAX_TREE_FILES:
            truncated = True
            break
        candidates.append(item)
    for item in candidates:
        rel = relative_path(root, item)
        language = LANGUAGES.get(item.suffix.lower())
        files.append(SourceFileEntry(path=rel, size_bytes=item.stat().st_size, language=language))
        if language:
            languages[language] = languages.get(language, 0) + 1
        if item.name in MANIFEST_NAMES:
            manifests.append(rel)
    files.sort(key=lambda f: f.path)
    manifests.sort()
    languages = dict(sorted(languages.items()))
    data = SourceTreeResult(
        path=relative_path(root, start), files_returned=len(files), files=files,
        manifests=manifests, languages=languages,
    ).model_dump(mode="json")
    return data, truncated


async def inspect_source_tree(target: str, path: str = ".", max_depth: int = 4) -> dict[str, Any]:
    root = _validate_root(target)
    data, truncated = await asyncio.to_thread(_tree, root, path, max_depth)
    return envelope(f"{data['files_returned']} source files listed", data, truncated=truncated)


def _read(
    root: Path, path: str, start_line: int, end_line: int | None
) -> tuple[dict[str, Any], bool]:
    if not isinstance(start_line, int) or isinstance(start_line, bool) or start_line < 1:
        raise _invalid("E_INVALID_ARGUMENT", "line range is invalid")
    if end_line is not None and (
        not isinstance(end_line, int) or isinstance(end_line, bool) or end_line < start_line
    ):
        raise _invalid("E_INVALID_ARGUMENT", "line range is invalid")
    file_path = _resolve_relative(root, path, reject_symlink=True)
    if not file_path.is_file() or not is_exposure_safe(file_path):
        raise _invalid("E_UNSUPPORTED_INPUT", "source file cannot be exposed")
    text = _read_text(file_path)
    lines = text.splitlines(keepends=True)
    total = len(lines)
    requested_end = end_line if end_line is not None else total
    actual_end = min(requested_end, start_line + MAX_READ_LINES - 1, total)
    selected = "".join(lines[start_line - 1 : actual_end]) if start_line <= total else ""
    truncated = requested_end > actual_end or len(selected) > MAX_READ_CHARS
    selected = selected[:MAX_READ_CHARS]
    actual_end = min(actual_end, total)
    data = SourceFileResult(
        path=relative_path(root, file_path), start_line=start_line, end_line=actual_end,
        total_lines=total, content=selected,
    ).model_dump(mode="json")
    return data, truncated


async def read_source_file(
    target: str, path: str, start_line: int = 1, end_line: int | None = None
) -> dict[str, Any]:
    root = _validate_root(target)
    data, truncated = await asyncio.to_thread(_read, root, path, start_line, end_line)
    return envelope(f"read {data['path']}", data, truncated=truncated)


def _search(root: Path, query: str, path: str, case_sensitive: bool) -> tuple[dict[str, Any], bool]:
    if not isinstance(query, str) or not query or len(query) > MAX_QUERY_LENGTH or "\x00" in query:
        raise _invalid("E_INVALID_ARGUMENT", "query is invalid")
    if not isinstance(case_sensitive, bool):
        raise _invalid("E_INVALID_ARGUMENT", "case_sensitive is invalid")
    start = _resolve_relative(root, path, reject_symlink=True)
    if not start.is_dir():
        raise _invalid("E_INVALID_ARGUMENT", "path is not a directory")
    needle = query if case_sensitive else query.casefold()
    matches: list[SourceMatch] = []
    files_searched = 0
    truncated = False
    for item in _iter_files(root, start, exposure=True):
        try:
            text = _read_text(item)
        except ToolError:
            continue
        files_searched += 1
        for line_no, line in enumerate(text.splitlines(), 1):
            haystack = line if case_sensitive else line.casefold()
            offset = haystack.find(needle)
            while offset >= 0:
                matches.append(
                    SourceMatch(
                        path=relative_path(root, item), line=line_no, column=offset + 1,
                        snippet=line[:MAX_SNIPPET_CHARS],
                    )
                )
                if len(matches) >= MAX_SEARCH_MATCHES:
                    truncated = True
                    break
                offset = haystack.find(needle, offset + max(1, len(needle)))
            if truncated:
                break
        if truncated:
            break
    matches.sort(key=lambda match: (match.path, match.line, match.column))
    data = SourceSearchResult(
        path=relative_path(root, start), query=query, case_sensitive=case_sensitive,
        files_searched=files_searched, matches=matches,
    ).model_dump(mode="json")
    return data, truncated


async def search_source(
    target: str, query: str, path: str = ".", case_sensitive: bool = False
) -> dict[str, Any]:
    root = _validate_root(target)
    data, truncated = await asyncio.to_thread(_search, root, query, path, case_sensitive)
    return envelope(f"{len(data['matches'])} source matches found", data, truncated=truncated)


__all__ = [
    "inspect_source_tree", "read_source_file", "search_source", "is_analyzer_safe",
    "is_exposure_safe", "relative_path", "_resolve_relative", "_validate_root",
]
