# kiro-classification: public
"""Property 2: wire representation round-trip under the deterministic profile (R8.5).

R8.5 says that deserialising a wire representation and serialising the result reproduces the
representation. The design's Property 2 states the stronger form the deterministic profile makes
available — the bytes are *identical*, not merely equivalent — and adds the half without which the
first is vacuous: **for all parseable representations that violate the profile, the codec raises a
decode error rather than accepting them**.

The second half is the load-bearing one. Byte identity holds by construction only if the decoder
refuses every representation the encoder could not have emitted. A decoder that accepted an
indefinite-length string, a non-shortest head, or a map whose keys are out of order would return a
perfectly good value, and re-encoding that value under the profile would produce *different bytes
than arrived*. Such a codec satisfies R8.2 and R8.3 and fails R8.5 silently, with nothing in the
decoded value to show it. So the two halves are one property and are asserted together, over one
drawn message: the canonical encoding round-trips, and each rewrite of it is refused.

#### `cbor2` is the oracle, never the authority

`cbor2` is pinned (R15.8) and appears here for exactly one purpose: to witness that a variant is
an *equivalent* rewrite rather than damaged bytes. A permissive reader parses it and returns the
same value the canonical encoding decodes to, so refusing it is a statement about the profile and
not about well-formedness — which is what makes the refusal a requirement rather than a taste.

What `cbor2` is not is a definition of canonical form, and the property never treats it as one.
`cbor2.dumps(..., canonical=True)` still applies RFC 7049 §3.9's shortest-encoding-first key
order, which RFC 8949 §4.2.1 replaced with a plain bytewise comparison of the encoded keys; the
two disagree the moment a map's keys differ in head width, and `{-1: 0, 24: 0}` is `a22000181800`
under `cbor2` against `a21818002000` under the profile. Canonical form here is
`protocol._cbor.scan` and `protocol.codec.profile`, and nothing else. A property that round-tripped
through `cbor2` and called the agreement R8.5 would be asserting R8.2 and R8.3 twice.

#### Which error a refusal surfaces as

Both, depending on where the rewrite lands, and the property allows exactly the two the decode
algorithm can produce:

* `VERSION_IDENTITY` — Phase 0 scans the whole representation before reading the version, so an
  indefinite length, a non-shortest head, or a transposition that displaces envelope key `1` is
  refused there, as a decode error naming the version key.
* `ROOT_IDENTITY` — a transposition inside a *nested* map leaves the version readable and
  supported, so Phases 0 and 1 pass and the profile check in Phase 2 objects. `NonCanonicalEncoding`
  surfaces as a decode error at root identity: no field is at fault, the whole representation is.

Never `VersionError`. Every rewrite leaves the version's *value* alone, so Phase 1 has nothing to
object to, and a version error here would mean the phase order had gone wrong rather than the
profile check.
"""

from __future__ import annotations

from typing import Final

import cbor2
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from protocol.codec import (
    ROOT_IDENTITY,
    VERSION_IDENTITY,
    DecodeError,
    NonCanonicalEncoding,
    Value,
    VersionError,
    decode,
    decode_value,
    encode,
    encode_value,
)
from protocol.generators import NonCanonical, message, non_canonical_variant
from protocol.generators.messages import Envelope
from protocol.generators.wire import Violation
from protocol.schema import load_catalogue
from tests.harness import CODEC_EXAMPLES

CATALOGUE = load_catalogue()

#: The two field identities a profile refusal can surface as. Not a wildcard: a refusal reported
#: against a *schema* field would mean the profile check had been reached after validation.
REFUSAL_IDENTITIES: Final = frozenset({VERSION_IDENTITY, ROOT_IDENTITY})

#: Derandomised draws per canonical encoding for the coverage assertion below. The rewrite pool is
#: dominated by non-shortest heads — one per widenable head per wider width — so the rarest rule
#: needs enough draws to be a claim rather than a hope.
RULE_DRAWS: Final = 200


@st.composite
def wire_case(draw: st.DrawFn) -> NonCanonical:
    """One canonical encoding and one non-deterministic rewrite of it.

    Both halves of Property 2 from one draw, over the domain the design names: the canonical
    encoding is `encode(message())`, and the rewrite is `non_canonical_variant()` of that same
    encoding, which the drawn `NonCanonical` carries as `canonical`. Composing them here rather
    than in two tests is what lets the refusal be stated against the encoding it would have been
    mistaken for — the bytes a permissive decoder would have re-emitted are on hand.
    """
    canonical = encode(draw(message()))
    return draw(non_canonical_variant(canonical))


# Feature: aws-serverless-agent-sandbox, Property 2: For all wire representations produced by the
# codec, deserialising a representation and then serialising the result produces bytes identical
# to the input; and for all parseable representations that violate the deterministic encoding
# profile, the codec raises a decode error rather than accepting them.
@given(case=wire_case())
@settings(
    max_examples=CODEC_EXAMPLES,
    # The generators read the cached catalogue on every draw, which Hypothesis reports as slow
    # data generation on the first example only.
    suppress_health_check=[HealthCheck.too_slow],
)
def test_wire_representations_round_trip_and_non_canonical_ones_are_refused(
    case: NonCanonical,
) -> None:
    canonical = case.canonical
    where = f"{case.violation} at byte {case.at} of {canonical.hex()}"

    # --- First half: wire -> message -> wire is the identity on bytes ------------------------
    assert encode(decode(canonical)) == canonical, (
        f"re-encoding {canonical.hex()} produced {encode(decode(canonical)).hex()}"
    )
    # R8.5's own weaker words, which byte identity implies and which are asserted anyway: a
    # future encoder that reproduced the bytes by copying them would pass the line above.
    assert decode(encode(decode(canonical))) == decode(canonical)

    # --- The rewrite is equivalent, not damaged ----------------------------------------------
    # A permissive reader parses the variant and returns the value the canonical encoding
    # carries, so nothing about it is ill-formed and the refusal below is the profile's alone.
    permissive = cbor2.loads(case.wire)
    assert permissive == cbor2.loads(canonical), where

    # And this is why accepting it would break R8.5 rather than merely being untidy: the only
    # profile-conforming encoding of that value is the canonical one, so a decoder that admitted
    # the variant would re-emit bytes the caller never sent.
    assert case.wire != canonical, where
    assert encode_value(_as_value(permissive)) == canonical, where

    # --- Second half: the codec refuses it --------------------------------------------------
    with pytest.raises(NonCanonicalEncoding):
        decode_value(case.wire)

    with pytest.raises(DecodeError) as raised:
        decode(case.wire)
    # A decode error and not a version error: the rewrite leaves the version's value alone, so a
    # `VersionError` would mean the phase order, not the profile, had decided this.
    assert not isinstance(raised.value, VersionError), where
    assert raised.value.field in REFUSAL_IDENTITIES, (
        f"{where} was refused against field {raised.value.field!r}, which is neither the version "
        f"key nor root identity"
    )


def test_every_rule_of_the_profile_is_refused_in_every_message_type() -> None:
    """Each of the four rules is reached *and refused*, per message type, deterministically.

    Not a property test and no tag: it draws from one strategy rather than quantifying over a
    domain, and Property 2 above is the one test that implements Property 2. It exists because the
    property's second half is only as wide as the rules its run happened to draw, and "every rule
    was exercised" has to be an assertion rather than an artefact of a seed. Per message type
    rather than over the union, so a rule reachable only in the one type that carries a nested map
    is a failure here instead of a silent narrowing.
    """
    for t in CATALOGUE.message_types:
        canonical = encode(_one(message(types=[t])))
        refused: dict[Violation, str] = {}
        for variant in _sample(non_canonical_variant(canonical), RULE_DRAWS):
            with pytest.raises(NonCanonicalEncoding):
                decode_value(variant.wire)
            with pytest.raises(DecodeError) as raised:
                decode(variant.wire)
            refused[variant.violation] = raised.value.field
        assert set(refused) == set(Violation), (
            f"{t}: only reached {sorted(str(rule) for rule in refused)}"
        )
        assert set(refused.values()) <= REFUSAL_IDENTITIES, f"{t}: {refused}"


def test_the_permissive_reader_is_not_the_authority_on_canonical_form() -> None:
    """The reason `cbor2` appears above as an oracle and nowhere as a definition.

    `cbor2.dumps(..., canonical=True)` orders map keys shortest-encoding-first, which RFC 8949
    §4.2.1 replaced with a bytewise comparison of the encoded keys. A codec that took the library's
    canonical form for the profile's would emit these bytes, and this codec's decoder would refuse
    its own output.
    """
    keys: dict[Value, Value] = {-1: 0, 24: 0}
    library = cbor2.dumps(keys, canonical=True)
    profile = encode_value(keys)
    assert library.hex() == "a22000181800"
    assert profile.hex() == "a21818002000"
    with pytest.raises(NonCanonicalEncoding):
        decode_value(library)
    assert decode_value(profile) == keys


# --- Helpers ---------------------------------------------------------------------------------


def _as_value(decoded: object) -> Value:
    """Narrow what the permissive reader returned to the protocol's value space.

    The reader is not typed against `Value`, and the encoder refuses anything outside it, so a
    variant that decoded to something the protocol cannot carry would fail here rather than
    reaching `encode_value` as an untyped object.
    """
    match decoded:
        case bool() | int() | str() | bytes():
            return decoded
        case list():
            return [_as_value(item) for item in decoded]
        case dict():
            return {_as_value(key): _as_value(item) for key, item in decoded.items()}
        case _:  # pragma: no cover - no rewrite here produces a value outside the space
            raise AssertionError(f"{decoded!r} is outside the protocol's value space")


def _sample[T](strategy: st.SearchStrategy[T], count: int) -> list[T]:
    """Draw `count` examples from `strategy`, the same list on every run.

    Hypothesis as a sampler rather than as a runner, which is what a coverage claim over one
    strategy needs: `derandomize` fixes the seed and no database is consulted, so the claim gives
    the same answer locally and in CI instead of being a coin toss dressed as an assertion.
    """
    drawn: list[T] = []

    def collect(value: T) -> None:
        drawn.append(value)

    profile = settings(
        max_examples=count,
        derandomize=True,
        database=None,
        deadline=None,
        suppress_health_check=list(HealthCheck),
    )
    given(value=strategy)(profile(collect))()
    return drawn


def _one(strategy: st.SearchStrategy[Envelope]) -> Envelope:
    return _sample(strategy, 1)[0]
