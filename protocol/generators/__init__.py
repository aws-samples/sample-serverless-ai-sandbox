# kiro-classification: public
"""Shared generators for the Sandbox_Protocol property suites (R8.4, R8.9).

Generators live with the protocol rather than with the tests, and they are derived from
`protocol/messages.yaml` through `protocol.schema` rather than restating any message shape. A
field added to the catalogue is populated by `message()` with no edit here; a field whose type
changes is drawn from the new type or fails loudly. The alternative — generators that list the
fields they know about — narrows silently when the schema moves, and a round-trip property that
no longer covers a field still passes.

Six generators, one per name the design's Properties 1 through 5 use:

| Generator | Property | Domain |
| --- | --- | --- |
| `message()` | 1 | Valid messages, byte fields adversarial, integer fields at their declared boundaries |
| `non_canonical_variant()` | 2 | Parseable encodings that violate the deterministic profile |
| `output_bytes()` | 3, 5 | Byte sequences a process may write, including invalid UTF-8 |
| `malformed()` | 4 | The four fault classes the decode phase order must discriminate |
| `command_spec()` | 5 | An exit code and an interleaved stdout and stderr schedule |
| `path_component()` | 5 | One filesystem name, which need not be valid UTF-8 |

Both languages' suites consume them. The TypeScript half lives alongside this module, in
`catalogue.ts`, `byteDomains.ts` and `messages.ts`, and it reads two generated mirrors rather
than declaring anything twice: `catalogue.json` from `messages.yaml`, and `byte_domains.json`
from `byte_domains.py`. See `export_catalogue.py` and `export_byte_domains.py` for why the
mirrors exist instead of a second YAML parser and a second copy of the byte domains, and for how
a stale one is caught. `tsconfig.json` typechecks that half; `protocol/generators/tsconfig.json`
explains why it needs its own.

The TypeScript counterparts of `non_canonical_variant()` and `malformed()` arrive with the
TypeScript codec, because both are parameterised by a canonical encoder and there is no
TypeScript encoder to hand one yet. `Fault` is a declaration rendered by an injected encoder for
exactly that reason: the same fault can be rendered by either language's codec.
"""

from __future__ import annotations

from protocol.generators.byte_domains import (
    ADVERSARIAL_BYTE_CLASSES,
    ADVERSARIAL_BYTE_SEQUENCES,
    CBOR_LENGTH_BOUNDARIES,
    MAX_OUTPUT_BYTES,
    MAX_PATH_COMPONENT_BYTES,
    output_bytes,
    path_component,
)
from protocol.generators.faults import (
    Encoder,
    Expectation,
    Fault,
    FaultClass,
    FaultKind,
    SchemaViolation,
    Scope,
    Violated,
    malformed,
    out_of_range_versions,
    violation_targets,
)
from protocol.generators.messages import (
    Envelope,
    Value,
    body,
    correlation_id,
    integer_boundaries,
    message,
    message_of,
    value_for,
)
from protocol.generators.runtime import (
    STDERR,
    STDOUT,
    Chunk,
    CommandSpec,
    command_spec,
)
from protocol.generators.wire import NonCanonical, Violation, non_canonical_variant

__all__ = [
    "ADVERSARIAL_BYTE_CLASSES",
    "ADVERSARIAL_BYTE_SEQUENCES",
    "CBOR_LENGTH_BOUNDARIES",
    "MAX_OUTPUT_BYTES",
    "MAX_PATH_COMPONENT_BYTES",
    "STDERR",
    "STDOUT",
    "Chunk",
    "CommandSpec",
    "Encoder",
    "Envelope",
    "Expectation",
    "Fault",
    "FaultClass",
    "FaultKind",
    "NonCanonical",
    "SchemaViolation",
    "Scope",
    "Value",
    "Violated",
    "Violation",
    "body",
    "command_spec",
    "correlation_id",
    "integer_boundaries",
    "malformed",
    "message",
    "message_of",
    "non_canonical_variant",
    "out_of_range_versions",
    "output_bytes",
    "path_component",
    "value_for",
    "violation_targets",
]
