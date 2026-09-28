# kiro-classification: public
"""Property 1: Protocol message round-trip (R8.2, R8.3, R8.4).

R8.4 is the criterion; R8.2 and R8.3 are the two functions it composes. The design's generator
for this property draws a message type from the catalogue and populates its body from that
type's schema, with byte-string fields drawn from arbitrary byte sequences including empty, and
integer fields drawn from the boundaries of their declared ranges. That generator is
`protocol.generators.message()` and it is imported rather than restated: it reads the same
`messages.yaml` the codec validates against, so a field added to the catalogue is covered here
with no edit and a field whose type changes is drawn from the new type or fails loudly.

One file per property, so the four codec properties can be written and read independently. The
TypeScript restatement of this same property is in `properties.test.ts` beside this module, over
the same generator; the numbers overlap by design and uniqueness is asserted per language.

`CODEC_EXAMPLES` rather than the suite floor, because the design's Testing Strategy sets 1,000
for Properties 1 through 4: they are pure functions over byte and integer domains where
iterations are nearly free and the failure modes are subtle.

**Equality is structural and type-strict.** Python's `==` would nearly do — `{1: b"\\xff"} ==
{1: b"\\xff"}` is true, which is why `equal.ts` exists only on the TypeScript side — but it
equates `True` with `1` and `False` with `0`. The catalogue declares boolean fields and integer
fields, so a codec that returned `1` where `True` was sent would satisfy `==` while handing its
caller a different value than the one it was given. `_identity` renders the type alongside the
value so that case fails. It is a strengthening of the assertion, not a widening: any pair it
accepts, `==` accepts too. It also makes a failure readable, since a diff of two rendered
identities says which field differs.
"""

from __future__ import annotations

from hypothesis import given, settings

from protocol.codec import Message, Value, decode, encode
from protocol.generators import Envelope, message
from tests.harness import CODEC_EXAMPLES

__all__ = ["test_every_valid_message_survives_a_round_trip"]


def _identity(value: Value) -> str:
    """A total rendering of a protocol value, equal exactly when the values are equal.

    Maps render their entries sorted, so two maps built in different insertion orders render
    the same: CBOR fixes an order for the *encoding*, not for the value. `bool` is matched
    before `int` because `bool` is a subclass of it, which is the whole reason this function
    exists rather than `==`.
    """
    match value:
        case bool():
            return f"bool:{value}"
        case int():
            return f"int:{value}"
        case bytes():
            return f"bytes:{value.hex()}"
        case str():
            return f"text:{value!r}"
        case list():
            return "list:[" + ",".join(_identity(item) for item in value) + "]"
        case dict():
            entries = sorted(
                f"{_identity(key)}=>{_identity(item)}" for key, item in value.items()
            )
            return "map:{" + ",".join(entries) + "}"


def message_identity(envelope: Message) -> str:
    """`_identity` for the envelope map.

    Separate because a `Message` is a `dict[int, Value]` and a `Value`'s map arm is a
    `dict[Value, Value]`; `dict` is invariant in its key type, so the one is not the other to a
    type checker however interchangeable they look at runtime.
    """
    entries = sorted(
        f"{_identity(key)}=>{_identity(item)}" for key, item in envelope.items()
    )
    return "map:{" + ",".join(entries) + "}"


# Feature: aws-serverless-agent-sandbox, Property 1: For any valid Sandbox_Protocol message,
# serialising it and then deserialising the result produces a message equal to the original.
@given(drawn=message())
@settings(max_examples=CODEC_EXAMPLES)
def test_every_valid_message_survives_a_round_trip(drawn: Envelope) -> None:
    round_tripped = decode(encode(drawn))

    assert message_identity(round_tripped) == message_identity(drawn), (
        f"round trip changed the message\n  sent: {drawn!r}\n  back: {round_tripped!r}"
    )


def test_the_identity_rendering_discriminates_a_boolean_from_an_integer() -> None:
    """Not a property and it draws nothing: the assertion's oracle, checked once.

    Both pairs below are `==` in Python. If either compared equal here, the property above
    would be weaker than the sentence it is tagged with.
    """
    assert {1: True} == {1: 1} and _identity({1: True}) != _identity({1: 1})
    assert {1: False} == {1: 0} and _identity({1: False}) != _identity({1: 0})

    # And the parts `==` already gets right, so the rendering is not merely different but right.
    assert _identity({1: b"\xff\xfe"}) == _identity({1: b"\xff\xfe"})  # nosemgrep: eqeq-is-bad — testing round-trip identity
    assert _identity({1: b"\xff"}) != _identity({1: b"\xfe"})
    assert _identity({1: 2, 3: 4}) == _identity({3: 4, 1: 2})
    assert _identity([1, 2]) != _identity([2, 1])
    assert _identity("1") != _identity(1)
