# kiro-classification: public
"""Reading a decoded request body by field name, and building a reply body by field name.

`runtime.operations` fixes what an operation returns — a message type and a body keyed by the
catalogue's field numbers. That keying is right for the wire and wrong for an operation's own
code, where `body[1]` says nothing about which field it is and stops being true the first time a
field order changes. So an operation reads and writes named fields, and this module is the one
place that turns a name into the key the catalogue assigns it. Nothing here hardcodes an integer.

It also fixes the one thing every operation needs and the catalogue does not obviously provide: a
way to refuse. The Sandbox_Protocol declares exactly two error types, and neither is "no such
file". The temptation is to reach for a status code instead, and that is the trap this module
exists to avoid, because the interesting status codes are already spoken for by the Client_SDK's
documented recovery paths: `401` and `403` send it to the Control_Plane to refresh a credential
and retry (R9.5), and `404` and `410` send it to re-resolve the Affinity_Key (R9.12). A missing
file answered with `404` would therefore be answered by the SDK tearing down and re-resolving a
Session that is working perfectly. A refused path is not a transport condition and must not
borrow a transport condition's code.

What it is instead is `error.decode`, whose declared shape is precisely a field identity and a
detail (R8.6). A path that resolves outside the configured root *is* an offending field, named as
the catalogue names it. The alternative — a third error type — would be an edit to
`protocol/messages.yaml`, which is the schema both codecs and the vector corpus are built from,
made to improve an error message. `runtime.protocol_handler` already declines that trade for
readiness and routing; this declines it for operations.

The refusal deliberately does not echo the offending path back in `detail`. The caller sent the
path and the envelope's correlation identifier ties the reply to the request that carried it, so
echoing adds nothing — and `detail` is text while a path is bytes, so echoing one would mean
choosing a lossy rendering of a value whose whole point is that it is not text.
"""

from __future__ import annotations

from collections.abc import Mapping

from protocol.codec.values import Message, Value
from protocol.schema import ENVELOPE_KEY_BODY, ENVELOPE_KEY_TYPE, Catalogue
from runtime.operations import OperationReply
from runtime.protocol_handler import ERROR_DECODE

__all__ = [
    "OperationRefusal",
    "as_bool",
    "as_bytes",
    "as_uint",
    "named_body",
    "refusal_reply",
    "request_fields",
]


class OperationRefusal(Exception):
    """An operation will not do what it was asked, and names the field at fault.

    Raised rather than returned so that a refusal can come from deep inside a path walk without
    every intermediate frame having to carry a reply back out. The operation catches it at its
    own boundary and renders it with `refusal_reply`; nothing above the operation sees it, which
    keeps `SandboxProtocolHandler.handle`'s promise never to raise intact.
    """

    def __init__(self, field: str, detail: str) -> None:
        self.field = field
        self.detail = detail
        super().__init__(f"{field}: {detail}")


def refusal_reply(catalogue: Catalogue, refusal: OperationRefusal) -> OperationReply:
    """Render a refusal as the `error.decode` message the catalogue declares (R8.6)."""
    return OperationReply(
        t=ERROR_DECODE,
        body=named_body(
            catalogue,
            ERROR_DECODE,
            {"field": refusal.field, "detail": refusal.detail},
        ),
    )


def named_body(
    catalogue: Catalogue, t: str, fields: Mapping[str, Value]
) -> dict[Value, Value]:
    """Build a body for `t`, keyed by the field numbers the catalogue assigns its names."""
    message = catalogue.messages[t]
    return {message.field_by_name(name).key: value for name, value in fields.items()}


def request_fields(catalogue: Catalogue, request: Message) -> dict[str, Value]:
    """A decoded request's body, keyed by the field names of its own message type.

    Optional fields that the request omitted are absent rather than present-and-None, so a
    caller distinguishes "not sent" from "sent as something falsy" — which for `proc.status`'s
    exit code is the difference between a running process and one that exited zero.
    """
    t = _as_text(request[ENVELOPE_KEY_TYPE], ENVELOPE_KEY_TYPE)
    body = request[ENVELOPE_KEY_BODY]
    if not isinstance(body, dict):
        raise TypeError(f"decoded body of {t!r} is {type(body).__name__}, not a map")
    return {
        field.name: body[field.key]
        for field in catalogue.messages[t].body
        if field.key in body
    }


def as_bytes(value: Value, name: str) -> bytes:
    """Narrow a field the catalogue types as a byte string.

    Unreachable through `decode`, which validated the body against the catalogue before the
    operation ever saw it. Present so the narrowing is a check rather than a cast, and raising
    rather than refusing because a value of the wrong type here is a defect in this runtime, not
    a peer's malformed input — the peer's malformed input was already reported by the codec.
    """
    if isinstance(value, bytes):
        return value
    raise TypeError(f"field {name!r} is {type(value).__name__}, not bytes")


def as_bool(value: Value, name: str) -> bool:
    """Narrow a field the catalogue types as a boolean. See `as_bytes`."""
    if isinstance(value, bool):
        return value
    raise TypeError(f"field {name!r} is {type(value).__name__}, not a boolean")


def as_uint(value: Value, name: str) -> int:
    """Narrow a field the catalogue types as an unsigned integer. See `as_bytes`.

    `bool` is excluded explicitly: it is a subclass of `int` in Python but a distinct major-type
    value in CBOR, so accepting one here would let a boolean field masquerade as a number.
    """
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    raise TypeError(f"field {name!r} is {type(value).__name__}, not an integer")


def _as_text(value: Value, name: object) -> str:
    """Narrow an envelope value the catalogue types as text. See `as_bytes`."""
    if isinstance(value, str):
        return value
    raise TypeError(f"envelope key {name!r} is {type(value).__name__}, not text")
