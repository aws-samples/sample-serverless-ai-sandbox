# kiro-classification: public
"""Control_Plane responses, and the one fixed not-found response (R6.9, R6.22).

Most of this module is unremarkable plumbing. One object in it is a security boundary, and it is
worth saying exactly which and exactly why.

**The fixed not-found response.** R6.9 requires a request naming a Session that does not belong to
the caller's Tenant to return not-found and to exclude that Session's existence from the response.
The design's Layer 3 states the standard more precisely than "return 404": the response for another
Tenant's Session identifier must be *byte-identical* to the response for a well-formed identifier
that never existed anywhere. Anything less makes the Control_Plane an oracle. An attacker holding a
Session identifier — an Affinity_Key holder, a leaked log line, a former tenant — could otherwise
ask "does this exist?" and get an answer, and an identifier echoed back in an error message would
confirm they had guessed a real one.

Byte-identity is achieved by construction rather than by care:

- :data:`NOT_FOUND_BODY` is a module-level ``bytes`` constant. It contains no format placeholder,
  so no interpolation site exists that a later change could route an identifier into. The body
  names no Session, no Tenant, no request and no reason.
- :data:`NOT_FOUND_RESPONSE` is a single frozen instance, and :func:`not_found` returns that same
  instance rather than building an equal one. The two paths R6.9 compares therefore return the
  identical object, so they cannot differ in the body, in the status, or in the header set.
- The headers are fixed too, and deliberately few. Nothing correlated with the request appears in
  them: no request identifier, no Tenant, no `Retry-After`, no diagnostic. `Content-Length` is
  computed by the platform from a body that is one constant, so it is the same number both times.

**What this does not claim.** The design settles this explicitly: latency is *not* artificially
equalised, and no constant-time guarantee is offered or needed. Both cases are the same operation —
one `GetItem` that returns no item, against the caller's own partition — so there is no second code
path whose duration could differ. See :mod:`control_plane.api.lookup`, which has no branch for
"exists but belongs to another Tenant" because the read it issues cannot see such a row. What is
outside this repository's control is API Gateway's own per-request identifier header, which varies
on every response including two identical ones, so it carries no information about the input and is
not an oracle.

Nothing here emits a log record. A not-found that logged the identifier, or that logged on one of
the two paths and not the other, would reintroduce through the log what the response body does not
say; lifecycle audit emission is its own component and its own task.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from http import HTTPStatus
from typing import Any, Final

__all__ = [
    "FIXED_HEADERS",
    "FORBIDDEN_BODY",
    "FORBIDDEN_RESPONSE",
    "JSON_MEDIA_TYPE",
    "NOT_FOUND_BODY",
    "NOT_FOUND_RESPONSE",
    "ControlPlaneError",
    "HttpResponse",
    "MalformedRequest",
    "OperationNotImplemented",
    "SessionNotFound",
    "UnauthenticatedRequest",
    "error_response",
    "forbidden",
    "json_response",
    "not_found",
]

JSON_MEDIA_TYPE: Final = "application/json"

#: The header set of every response this module builds, as an ordered pair sequence so a response
#: is fully immutable. `no-store` because a cached not-found would answer a later question about a
#: Session that by then exists, and because no Control_Plane response is a cacheable resource.
FIXED_HEADERS: Final[tuple[tuple[str, str], ...]] = (
    ("content-type", JSON_MEDIA_TYPE),
    ("cache-control", "no-store"),
)


@dataclass(frozen=True, slots=True)
class HttpResponse:
    """One response, as the bytes and status that leave the handler.

    The body is `bytes` rather than a mapping, and the headers are a tuple of pairs rather than a
    dict, so that a response is a value with one serialisation. That is what lets the fixed
    not-found response be a shared constant, and what lets a test compare two responses for
    byte-identity instead of comparing two dictionaries and hoping the renderer is deterministic.
    """

    status: int
    body: bytes
    headers: tuple[tuple[str, str], ...] = FIXED_HEADERS

    def to_payload(self) -> dict[str, Any]:
        """Render the API Gateway HTTP API payload-format-2.0 proxy response."""
        return {
            "statusCode": int(self.status),
            "headers": dict(self.headers),
            "body": self.body.decode("utf-8"),
            "isBase64Encoded": False,
        }

    def to_bytes(self) -> bytes:
        """Serialise status, headers and body into one comparable byte string.

        Exists for the assertion R6.9 needs. Comparing whole responses field by field invites a
        test that checks the body and forgets a header, which is precisely the variance an
        information-disclosure boundary has to exclude. Header names are lowercased and sorted so
        that a difference in declaration order is not mistaken for a difference in the response.
        """
        head = f"{int(self.status)}\n".encode()
        rendered = b"".join(
            f"{name.lower()}: {value}\n".encode()
            for name, value in sorted(self.headers)
        )
        return head + rendered + b"\n" + self.body


def _body(payload: dict[str, Any]) -> bytes:
    """Serialise a response body deterministically.

    Sorted keys and fixed separators, so two equal bodies are equal as bytes.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


#: The one not-found body. A literal rather than a serialised mapping, because a literal has no
#: interpolation site: there is nowhere in this expression an identifier could later be added.
#: Any change to these bytes must keep them free of anything derived from a request.
NOT_FOUND_BODY: Final = b'{"error":"NotFound","message":"No such Session."}'

#: The single fixed not-found response (R6.9). Returned by identity, never rebuilt.
NOT_FOUND_RESPONSE: Final = HttpResponse(
    status=HTTPStatus.NOT_FOUND, body=NOT_FOUND_BODY, headers=FIXED_HEADERS
)

#: The handler's own fail-closed refusal. Reached only when an invocation carries no evidence that
#: the `AWS_IAM` authorizer ran, or when the Tenant of a verified caller cannot be resolved. Fixed
#: for the same reason as the not-found body: there is nothing safe to say about an identity the
#: handler could not establish.
FORBIDDEN_BODY: Final = b'{"error":"Forbidden","message":"Request is not authorized."}'

FORBIDDEN_RESPONSE: Final = HttpResponse(
    status=HTTPStatus.FORBIDDEN, body=FORBIDDEN_BODY, headers=FIXED_HEADERS
)


def not_found() -> HttpResponse:
    """Return *the* fixed not-found response.

    One function, one constant, no arguments. A signature that accepted a Session identifier would
    be an invitation to interpolate it, so it does not accept one — the guarantee is in the type
    rather than in a reviewer noticing.
    """
    return NOT_FOUND_RESPONSE


def forbidden() -> HttpResponse:
    """Return the fixed authorization refusal."""
    return FORBIDDEN_RESPONSE


def json_response(status: int, payload: dict[str, Any]) -> HttpResponse:
    """Build a successful response from an operation result."""
    return HttpResponse(status=status, body=_body(payload), headers=FIXED_HEADERS)


def error_response(status: int, error: str, message: str) -> HttpResponse:
    """Build an error response that is allowed to say something.

    Distinct from :func:`not_found` on purpose. R6.5 requires the duration-ceiling rejection to
    name the provider's declared maximum, and R6.14 requires a provisioning failure to name the
    recorded reason, so those responses carry content. Neither concerns the existence of a Session
    belonging to somebody else, which is the one thing a Control_Plane response may not reveal.
    """
    return json_response(status, {"error": error, "message": message})


class ControlPlaneError(Exception):
    """A condition with a defined response in the design's error catalogue.

    Carrying the response rather than a status and a message means the dispatcher renders what the
    raiser decided, and a subclass whose response must be fixed can pin it.
    """

    def __init__(self, response: HttpResponse, detail: str = "") -> None:
        super().__init__(detail or f"HTTP {int(response.status)}")
        self.response = response


class SessionNotFound(ControlPlaneError):
    """The named Session is not addressable by this caller (R6.9).

    Raised both when no such Session exists anywhere and when it exists in another Tenant, because
    the read that produced this is confined to the caller's own partition and therefore cannot
    tell the two apart. The response is pinned to the shared constant here, so no raiser and no
    handler can supply a different one.
    """

    def __init__(self) -> None:
        super().__init__(NOT_FOUND_RESPONSE, "no such Session")


class UnauthenticatedRequest(ControlPlaneError):
    """The invocation carries no verified caller identity, or none that resolves to a Tenant."""

    def __init__(self, detail: str = "") -> None:
        super().__init__(FORBIDDEN_RESPONSE, detail or "request is not authorized")


class MalformedRequest(ControlPlaneError):
    """The request body is not a JSON object, so no operation can read a field from it."""

    def __init__(self, message: str) -> None:
        super().__init__(
            error_response(HTTPStatus.BAD_REQUEST, "MalformedRequest", message), message
        )


class OperationNotImplemented(ControlPlaneError):
    """A routed operation whose behaviour a later task of this component supplies.

    Present so that the route set can be complete before the operations behind it are, and so that
    the gap is a `501` naming the operation rather than a `500` from an attribute that does not
    exist. Every occurrence is expected to disappear as tasks 6.2 through 6.18 land.
    """

    def __init__(self, operation_name: str) -> None:
        message = f"{operation_name} is routed but not yet implemented"
        super().__init__(
            error_response(HTTPStatus.NOT_IMPLEMENTED, "NotImplemented", message),
            message,
        )
        self.operation_name = operation_name
