# kiro-classification: public
"""Property 4: error selection follows the decode phase order (R8.6, R8.7, R8.8).

One property, quantified over `protocol.generators.faults.malformed()`, which produces the four
fault classes the design's Property 4 names. The claim is not that a malformed representation is
refused — that is Property 2's territory and `test_codec.py`'s — but that *which* of the codec's
two error shapes arrives is decided by the phase order and by nothing else.

The fourth fault class is what makes this more than a restatement of R8.6 and R8.7. A
representation that is defective in two phases at once — an out-of-range version *and* a
single-field schema violation — has two errors available, and the phase order picks one:
`VersionError`, because Phase 1 completes before Phase 2 begins. `malformed()` draws that class
with a quarter of its weight and builds it as the full cross product of every out-of-range
version against every single-field violation reachable in the drawn message, so an
implementation that happened to order the phases correctly for one combination and not another
is caught rather than flattered. The assertions below check per example that such a draw really
does carry both faults, so "multiply defective" is a property of the input rather than a claim
about the generator.

Three things are deliberately *not* asserted here.

*The spelling of a body field's identity.* `Fault.identifies` fixes the spellings a decode error
may use and leaves the choice among them to the codec, and pinning one here would be this test
deciding an interface that belongs to `protocol.codec.validate`. The design fixes only the
envelope case — field `1` when the version is unreadable — and that one is asserted exactly.

*That `malformed()` reaches all four classes.* That is a claim about the strategy rather than
about the codec, and it is asserted where the strategy lives, in
`protocol.generators.test_generators.test_malformed_reaches_all_four_fault_classes`, over
derandomised draws. A sampled property cannot make a coverage assertion after its own run, and a
second copy of the claim here would drift from the first.

*Anything about `cbor2`.* The pinned library is a test oracle for the cases where an independent
encoder can be one, and `cbor2.loads` is permissive: it accepts representations the deterministic
profile refuses, so it cannot say what Phase 2 owes. Every expectation below is the
implementation's own error shape.

`test_codec.py` enumerates this domain exhaustively over the catalogue with no sampling, including
the cross product on every declared message type. That is the design's "asserted directly by a
test that constructs exactly that input"; this is the same claim over the sampled domain both
languages share, so a case that would catch the Python codec is one the TypeScript restatement in
`properties.test.ts` would also have drawn.
"""

from __future__ import annotations

from hypothesis import given, settings

from protocol.codec import (
    VERSION_IDENTITY,
    CodecError,
    DecodeError,
    VersionError,
    decode,
    encode,
)
from protocol.generators import Expectation, Fault, FaultClass, malformed
from protocol.schema import ENVELOPE_KEY_TYPE, load_catalogue
from tests.harness import CODEC_EXAMPLES

CATALOGUE = load_catalogue()


def _refusal(wire: bytes) -> CodecError:
    """Decode `wire` and return the error it was refused with.

    A malformed representation that decodes is the failure this property exists to catch, so
    returning nothing is not an option the caller has to handle.
    """
    try:
        decode(wire, catalogue=CATALOGUE)
    except CodecError as exc:
        return exc
    raise AssertionError("a malformed representation was accepted")


# Feature: aws-serverless-agent-sandbox, Property 4: For all malformed wire representations, the
# codec raises the error determined by the phase order and no other: an unreadable or misplaced
# version field raises a decode error naming field `1`; a readable but unsupported version raises
# a version error carrying the received version and both bounds of the supported range; a
# supported version with a schema violation raises a decode error naming the violated field; and a
# representation carrying both an unsupported version and a schema violation raises a version
# error.
@given(fault=malformed(catalogue=CATALOGUE))
@settings(max_examples=CODEC_EXAMPLES)
def test_error_selection_follows_the_decode_phase_order(fault: Fault) -> None:
    where = f"{fault.kind} on {fault.message[ENVELOPE_KEY_TYPE]!r}"

    # The input is defective in the phases its class says it is. Without this, the cross-product
    # class could degrade to a single fault and the ordering claim would still pass vacuously.
    if fault.fault_class is FaultClass.VERSION_UNSUPPORTED_AND_SCHEMA_VIOLATION:
        assert fault.version is not None, where
        assert not CATALOGUE.supports(fault.version), where
        assert fault.violated is not None, where

    error = _refusal(fault.render(encode))

    if fault.expectation is Expectation.VERSION_ERROR:
        # Phase 1 decided, so Phase 2 never ran and the field it would have named is unreported.
        assert isinstance(error, VersionError), f"{where}: {error!r}"
        assert not isinstance(error, DecodeError), where
        assert error.received == fault.version, where
        assert error.supported_min == CATALOGUE.supported_min, where
        assert error.supported_max == CATALOGUE.supported_max, where
        return

    assert isinstance(error, DecodeError), f"{where}: {error!r}"
    assert not isinstance(error, VersionError), where
    if fault.fault_class is FaultClass.VERSION_UNREADABLE:
        # No version was received, so a version error would report one that does not exist.
        assert error.field == VERSION_IDENTITY, where
    assert fault.identifies(error.field), (
        f"{where} was reported as {error.field!r}, which is not in "
        f"{sorted(fault.acceptable_field_identities)}"
    )
