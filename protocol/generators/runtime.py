# kiro-classification: public
"""`command_spec()`: declared exit codes and declared output, for Property 5.

The design's generator draws an exit code, an interleaving schedule of stdout and stderr
chunks, and chunk contents from `output_bytes()`. The schedule is the part that matters: the
property asserts that the concatenation of streamed chunks equals the finally captured output,
and a runtime that merged the two streams, or that reordered chunks within one, passes against
a schedule that never interleaves them.

The bounds come from the catalogue rather than from constants here — the exit code range from
`exec.result.exitCode`, the stream discriminator from `exec.chunk.stream` — so a change to
either in `messages.yaml` reaches this generator without an edit.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass
from typing import Final

from hypothesis import strategies as st
from hypothesis.strategies import SearchStrategy

from protocol.generators.byte_domains import output_bytes
from protocol.generators.messages import integer_boundaries
from protocol.schema import Catalogue, IntRange, load_catalogue

__all__ = [
    "MAX_CHUNKS",
    "MAX_CHUNK_BYTES",
    "STDERR",
    "STDOUT",
    "Chunk",
    "CommandSpec",
    "command_spec",
]

#: The `exec.chunk.stream` discriminator values, named rather than written as 0 and 1 at each
#: use site.
STDOUT: Final = 0
STDERR: Final = 1

#: A schedule long enough to interleave several times over. Longer schedules exercise the same
#: code path, and every chunk is a round trip through the runtime.
MAX_CHUNKS: Final = 8

#: Per-chunk ceiling. A chunk is one message on the wire, and the full byte domain is already
#: reached by the codec properties; here the interesting axis is the schedule, not the size.
MAX_CHUNK_BYTES: Final = 1024


@dataclass(frozen=True, slots=True)
class Chunk:
    """One streamed output chunk: which stream it belongs to and its bytes."""

    stream: int
    data: bytes


@dataclass(frozen=True, slots=True)
class CommandSpec:
    """A command's declared result: the exit code and the output it produces."""

    exit_code: int
    chunks: tuple[Chunk, ...]

    def _joined(self, stream: int) -> bytes:
        return b"".join(chunk.data for chunk in self.chunks if chunk.stream == stream)

    @property
    def stdout(self) -> bytes:
        """What a non-streaming `exec.result` must carry for stdout."""
        return self._joined(STDOUT)

    @property
    def stderr(self) -> bytes:
        """What a non-streaming `exec.result` must carry for stderr."""
        return self._joined(STDERR)

    @property
    def interleaves(self) -> bool:
        """Whether the schedule alternates streams at least once.

        A property asserting that streams stay separate is vacuous on a schedule that never
        alternates, so a test can require this rather than hope for it.
        """
        streams = [chunk.stream for chunk in self.chunks]
        return any(a != b for a, b in itertools.pairwise(streams))


def _range_of(catalogue: Catalogue, t: str, field: str) -> IntRange:
    range_ = catalogue.messages[t].field_by_name(field).spec.range
    if range_ is None:  # pragma: no cover - the loader rejects an unranged integer
        raise ValueError(f"{t}.{field} declares no range")
    return range_


def _exit_codes(catalogue: Catalogue) -> SearchStrategy[int]:
    """Exit codes, boundaries at raised weight.

    `exec.result.exitCode` is the one signed integer in the catalogue, because a negative value
    reports termination by signal N as -N. Its bounds and the sign transition are where an
    encoder that assumed unsigned fails.
    """
    range_ = _range_of(catalogue, "exec.result", "exitCode")
    return st.one_of(
        st.sampled_from(integer_boundaries(range_)),
        st.integers(min_value=range_.min, max_value=range_.max),
    )


def command_spec(*, catalogue: Catalogue | None = None) -> SearchStrategy[CommandSpec]:
    """A command with a declared exit code and a declared output schedule (R7.1, R7.2)."""
    resolved = catalogue if catalogue is not None else load_catalogue()
    stream_range = _range_of(resolved, "exec.chunk", "stream")

    chunk = st.builds(
        Chunk,
        stream=st.integers(min_value=stream_range.min, max_value=stream_range.max),
        data=output_bytes(max_size=MAX_CHUNK_BYTES),
    )
    return st.builds(
        CommandSpec,
        exit_code=_exit_codes(resolved),
        chunks=st.lists(chunk, max_size=MAX_CHUNKS).map(tuple),
    )
