"""Reading the handler back out of the repository.

Module 2 reports *where* a sink is - `src/index.js:73` - but the envelope
carries no source, by design: everything in it has passed through redaction
and is safe to store. For a selector deciding which parameter reaches that
sink, the location alone is thin. Line 73 is `await db.prepare(sql).all()`;
the answer is on line 72, where `sql` was built.

So the slice is read from the working tree, on request. The endpoint's
handler range comes from the route-binding evidence Module 2 already emits
(`metadata: {endpoint_id, file_path, start_line, end_line}`), which is how a
nineteen-line window can be quoted instead of one line without guessing.

Two deliberate boundaries:

Nothing above this module touches the filesystem. `generate` takes already
rendered text, so hypothesis generation still runs from a single JSON file
and a caller opts into source access explicitly.

The result is untrusted. It is text from a scanned application - comments
and string literals included - so it is line-numbered, capped, and handed to
the prompt framed as material to read rather than to obey.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from ..analysis.correlation import CorrelationRecord
from ..domain.analysis_models import Module2Output

#: Enough to hold a route handler without letting one long function crowd out
#: the rest of the prompt. A longer range is windowed around the sink.
MAX_SLICE_LINES = 60
MAX_SLICE_CHARS = 6000
#: Lines kept either side of the sink when a handler exceeds the cap.
WINDOW = 12


@dataclass(frozen=True)
class CodeRange:
    """A half-open-free, inclusive line span in one file, as Module 2 reports it."""

    file_path: str
    start_line: int
    end_line: int


def handler_ranges(output: Module2Output) -> dict[str, CodeRange]:
    """Endpoint id -> the line span of the code that handles it.

    Read from the route-binding evidence rather than recomputed: Module 2
    bound the route to the handler with a reviewed AST extractor, and
    re-deriving it here would be a second answer that could disagree.
    """
    ranges: dict[str, CodeRange] = {}
    for evidence in output.analysis_evidence_records:
        metadata = getattr(evidence, "metadata", None) or {}
        endpoint_id = metadata.get("endpoint_id")
        file_path = metadata.get("file_path")
        start = metadata.get("start_line")
        end = metadata.get("end_line")
        if not endpoint_id or not file_path or start is None or end is None:
            continue
        ranges[str(endpoint_id)] = CodeRange(str(file_path), int(start), int(end))
    return ranges


class SourceSlicer:
    """Reads line ranges out of one approved source root.

    Confined to `source_root`: a `file_path` that climbs out of it is refused
    rather than read. Module 2's paths are relative to the scanned root and
    should never escape it, so one that tries is a bug or worse, and either
    way not something to resolve quietly.
    """

    def __init__(
        self,
        source_root: str | Path,
        *,
        max_lines: int = MAX_SLICE_LINES,
        max_chars: int = MAX_SLICE_CHARS,
    ) -> None:
        self.source_root = Path(source_root).resolve()
        self.max_lines = max_lines
        self.max_chars = max_chars
        self.errors: list[str] = []

    def read(self, span: CodeRange, *, highlight: Sequence[int] = ()) -> str:
        """Render the span with line numbers, marking the lines that matter.

        The numbers are not decoration: they let a reader - or a model -
        line the quote up against `src/index.js:73` as Module 2 reported it,
        and they make it obvious when the window was trimmed.
        """
        lines = self._lines(span.file_path)
        if lines is None:
            return ""

        start, end = self._window(span, highlight, len(lines))
        marked = set(highlight)
        rendered: list[str] = []
        for number in range(start, end + 1):
            text = lines[number - 1].rstrip("\n")
            flag = ">" if number in marked else " "
            rendered.append(f"{flag} {number:>4} | {text}")

        body = "\n".join(rendered)
        if len(body) > self.max_chars:
            body = body[: self.max_chars] + "\n  ... (truncated)"
        if (start, end) != (span.start_line, span.end_line):
            body = (
                f"  (lines {start}-{end} of {span.start_line}-{span.end_line})\n{body}"
            )
        return body

    def _window(
        self, span: CodeRange, highlight: Sequence[int], total: int
    ) -> tuple[int, int]:
        start = max(1, span.start_line)
        end = min(total, span.end_line)
        if end - start + 1 <= self.max_lines:
            return start, end
        # Too long to quote whole: keep what surrounds the interesting line,
        # which is the part that explains how the value got there.
        focus = highlight[0] if highlight else start
        return (
            max(start, focus - WINDOW),
            min(end, focus + WINDOW),
        )

    def _lines(self, file_path: str) -> list[str] | None:
        candidate = (self.source_root / file_path).resolve()
        if not candidate.is_relative_to(self.source_root):
            self.errors.append(f"{file_path}: resolves outside the approved source root")
            return None
        try:
            return candidate.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            self.errors.append(f"{file_path}: {type(exc).__name__}: {exc}")
            return None


def slices_for_records(
    output: Module2Output,
    records: Sequence[CorrelationRecord],
    slicer: SourceSlicer,
) -> dict[str, str]:
    """Endpoint id -> its handler source, with the sink line marked.

    Keyed by endpoint because that is what a selection question is about: the
    selector is choosing among the parameters of one endpoint, and the code
    it needs is the code behind that endpoint.
    """
    ranges = handler_ranges(output)
    sinks = {item.sink_id: item for item in output.sink_candidates}
    rendered: dict[str, str] = {}

    for record in records:
        endpoint_id = record.endpoint_id
        if endpoint_id is None or endpoint_id in rendered:
            continue
        sink = sinks.get(record.sink_ref or "")
        span = ranges.get(endpoint_id)
        if span is None:
            # No route binding: fall back to the sink's own neighbourhood,
            # which is less context but still better than the bare line.
            if sink is None:
                continue
            span = CodeRange(
                sink.file_path,
                max(1, sink.start_line - WINDOW),
                (sink.end_line or sink.start_line) + WINDOW,
            )
        highlight = _sink_lines(sink, span)
        text = slicer.read(span, highlight=highlight)
        if text:
            rendered[endpoint_id] = text
    return rendered


def _sink_lines(sink: object, span: CodeRange) -> list[int]:
    if sink is None:
        return []
    start = getattr(sink, "start_line", None)
    if start is None or getattr(sink, "file_path", None) != span.file_path:
        return []
    end = getattr(sink, "end_line", None) or start
    return [number for number in range(int(start), int(end) + 1)]


def describe_slices(slices: Mapping[str, str]) -> str:
    """One line for logs: how many handlers were quoted."""
    return f"{len(slices)} handler slice(s)"
