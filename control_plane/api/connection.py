# kiro-classification: public
"""`RefreshConnection`: the route that hands a caller a replacement credential (R9.5).

`POST /sessions/{id}/connection`, `AWS_IAM` like every route. The operation itself is four lines,
which is the intended shape: every decision about what a credential may reach belongs to
:class:`~control_plane.credentials.ConnectionIssuer`, and this module's job is to reach it for the
Session the dispatcher already resolved and to render the result.

Three things it deliberately does not do.

**It does not compute a scope.** It passes the record and nothing else. R9.5's refresh must produce
a credential no broader than the original, and the way that is guaranteed is that this operation has
no way to ask for a broader one — :meth:`~control_plane.credentials.ConnectionIssuer.issue` takes
the record alone, so "refresh" and "issue at creation" are the same derivation over the same stored
state rather than two code paths that must be kept in agreement.

**It does not resolve the identifier.** The dispatcher does, inside the caller's own Tenant
partition, so R6.9's fixed not-found response is reached on this route by construction and a
cross-tenant Session identifier never reaches the mint. See
:mod:`control_plane.api.handlers`.

**It does not write the credential back to the Session row.** The published `connection` attribute
exists so that the creation response can be read from the State_Store rather than from a provider
call the handler issued (R6.13); nothing reads a *refreshed* credential from the row, so a write
here would be one write per client `401` in exchange for nothing. The refreshed credential goes to
the caller who asked for it and to no one else.

A Session that admits no credential — terminal, not yet provisioned, or past its maximum duration —
is a `409` naming the lifecycle state. That is safe to say and useful to hear: the record is in the
caller's own partition, so its state is not somebody else's secret, and `GetSession` would report
the same state anyway. The one thing a Control_Plane response may never reveal is the existence of
another Tenant's Session, and this response is reached only after the dispatcher established that
this Session is the caller's own.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from http import HTTPStatus
from typing import Any

from control_plane.api.errors import ControlPlaneError, error_response
from control_plane.api.handlers import (
    NotImplementedOperations,
    OperationRequest,
    OperationResult,
)
from control_plane.credentials import ConnectionIssuer, ConnectionNotIssuable
from control_plane.state.records import ConnectionDescriptor, SessionRecord

__all__ = [
    "ConnectionOperations",
    "ConnectionUnavailable",
    "connection_payload",
]


class ConnectionUnavailable(ControlPlaneError):
    """The named Session exists and is the caller's own, but admits no connection credential.

    `409` rather than `404`: not-found is reserved for a Session the caller cannot address at all,
    and answering this case with the fixed not-found response would tell a caller their own
    `PENDING` Session does not exist.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(
            error_response(HTTPStatus.CONFLICT, "ConnectionUnavailable", reason), reason
        )
        self.reason = reason


def connection_payload(
    record: SessionRecord, connection: ConnectionDescriptor
) -> dict[str, Any]:
    """The connection descriptor response of the design's Data Models section.

    `resolution` is absent, because that field exists only on `ResolveSession` where R6.15 requires
    a caller to be able to tell a resolve from a create. A refresh is neither.
    """
    return {
        "sessionId": record.session_id,
        "generation": record.generation,
        "lifecycleState": record.lifecycle_state.value,
        "connection": connection.to_map(),
    }


@dataclass(frozen=True, slots=True)
class ConnectionOperations(NotImplementedOperations):
    """The operations implemented by this task: `RefreshConnection`, and no other.

    Inherits the remaining seven seams so that the routes those tasks own keep answering `501`
    naming the task that fills them, rather than this class having to restate them or a partial
    implementation reaching the gateway as a `500`.
    """

    issuer: ConnectionIssuer = field(default_factory=ConnectionIssuer)

    def refresh_connection(self, request: OperationRequest) -> OperationResult:
        """Mint a replacement credential for the resolved Session and return the descriptor."""
        record = request.session
        if (
            record is None
        ):  # pragma: no cover - the route declares `{id}`, so this cannot happen
            raise ConnectionUnavailable("the request named no Session")
        try:
            connection = self.issuer.issue(record)
        except ConnectionNotIssuable as exc:
            raise ConnectionUnavailable(exc.reason) from exc
        return OperationResult(payload=connection_payload(record, connection))
