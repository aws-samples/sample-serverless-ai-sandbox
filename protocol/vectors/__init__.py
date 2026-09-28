# kiro-classification: public
"""The cross-implementation vector corpus: what the two codecs must agree on (R8.4, R8.5).

Properties 1 through 4 hold in Python and in TypeScript independently. That is not the same
claim as the two implementations agreeing on the wire, and the gap is not a technicality: two
codecs can each round-trip self-consistently while disagreeing byte for byte about how a value
is encoded, and every property in both suites would still pass. Nothing else in the suite
looks at both implementations at once, so this corpus is the only place wire agreement is
asserted.

The corpus closes the gap by fixing the wire in a committed artefact and then requiring four
things of it, two per language:

| Direction | Python | TypeScript |
| --- | --- | --- |
| Interpretation: bytes -> fields | `decode(wire)` matches the declared fields | the same |
| Production: fields -> bytes | `encode(declared) == wire` | the same |

The bytes are the Python codec's, written by `export_vectors.py`. The declared fields are
recorded alongside them, so "decoded field by field" is a comparison against stated values
rather than the absence of an exception. Both languages read the same two declarations and
assert both directions, which is what makes the reverse direction a fact rather than an
assumption: TypeScript's own encoding of the declared fields is asserted equal to `wire`, and
`wire` is what Python decodes, so the bytes TypeScript produces are bytes Python reads
correctly. A corpus that only asserted TypeScript could read Python's bytes would leave the
encoder half of the TypeScript codec unchecked against anything but itself.

Three files, because the three make different claims:

| File | Claim |
| --- | --- |
| `messages.json` | Every message type encodes and decodes identically in both languages |
| `values.json` | The profile's encoding rules, above all map key ordering, are the same rules |
| `rejections.json` | The two codecs refuse the *same* representations, with the same error |

`rejections.json` is not an extra. R8.5's byte identity holds only because the decoder refuses
every representation the encoder could not have emitted, so two codecs that accept different
sets do not agree on the wire however well their accepted sets round-trip. Agreement on
refusal is half of agreement.

The corpus is deterministic and committed. Hypothesis appears in the exporter as a
derandomised sampler and nowhere in either test: a corpus regenerated differently on every run
would make a cross-implementation check a coin toss, and a test that generated fresh vectors at
assert time would not be reading the artefact the other language reads. Neither test claims a
numbered property, because this is not one of the 44 — it is the check that the four the codec
does claim mean what they appear to mean.
"""

from __future__ import annotations

from protocol.vectors.model import (
    MESSAGES_JSON_PATH,
    REJECTIONS_JSON_PATH,
    VALUES_JSON_PATH,
    Expect,
    Index,
    Leaf,
    MapKey,
    MessageVector,
    Path,
    RejectionVector,
    Step,
    ValueVector,
    as_value,
    describe_path,
    from_tagged,
    leaves,
    load_messages,
    load_rejections,
    load_values,
    resolve,
    step_from_json,
    step_to_json,
    to_tagged,
)

__all__ = [
    "MESSAGES_JSON_PATH",
    "REJECTIONS_JSON_PATH",
    "VALUES_JSON_PATH",
    "Expect",
    "Index",
    "Leaf",
    "MapKey",
    "MessageVector",
    "Path",
    "RejectionVector",
    "Step",
    "ValueVector",
    "as_value",
    "describe_path",
    "from_tagged",
    "leaves",
    "load_messages",
    "load_rejections",
    "load_values",
    "resolve",
    "step_from_json",
    "step_to_json",
    "to_tagged",
]
