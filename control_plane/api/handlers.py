# kiro-classification: public
"""The dispatcher, and the eight seams the rest of this component fills in.

The shape here is deliberately thin. :class:`ControlPlaneApi` does four things and stops:

1. Establishes the authenticated principal, failing closed if the invocation carries no evidence
   that the `AWS_IAM` authorizer ran (R6.3). This happens **first**, before routing, so that an
   invocation with no verified caller is refused rather than being told which paths exist.
2. Routes onto one of the eight operations (R6.1). No match is the fixed not-found response.
3. For every route that names a Session, resolves that identifier inside the caller's own Tenant
   partition and hands the resulting record to the operation (R6.9). Doing this in the dispatcher
   rather than in each operation is the point: not-found is reached on all five such routes by
   construction, and no operation added later can forget it.
4. Renders the result, or the response an exception in the design's error catalogue carries.

Everything else is an :class:`SessionOperations` implementation, which is where the substance of
this component lives. The default one, :class:`NotImplementedOperations`, answers `501` and names
the task that fills each seam. That is a truthful skeleton rather than a stubbed-out lie: the route
set, the authorization posture and the not-found response are complete and testable now, and each
operation's behaviour arrives with the task that owns it.

An operation receives an :class:`OperationRequest` and returns an :class:`OperationResult`, so the
dispatch table is data. A per-operation request type would have meant eight signatures for the
dispatcher to know, and the fields that actually differ between operations are body fields, which
the operations parse for themselves.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from http import HTTPStatus
from typing import Any, Final, Protocol

from control_plane.api.errors import (
    ControlPlaneError,
    HttpResponse,
    OperationNotImplemented,
    json_response,
    not_found,
)
from control_plane.api.lookup import SessionLookup, resolve_session
from control_plane.api.request import (
    principal_for,
    request_body,
    request_method_and_path,
)
from control_plane.api.routes import (
    SESSION_ID_PARAMETER,
    Operation,
    RouteDefinition,
    route_for,
)
from control_plane.state.records import SessionRecord
from control_plane.tenancy import AuthenticatedPrincipal

__all__ = [
    "OPERATION_METHODS",
    "ControlPlaneApi",
    "NotImplementedOperations",
    "OperationRequest",
    "OperationResult",
    "SessionOperations",
    "lambda_entrypoint",
]


@dataclass(frozen=True, slots=True)
class OperationRequest:
    """One routed, authenticated request.

    `session` is populated for exactly the routes whose template carries `{id}`, and it is a
    resolved record rather than an identifier. An operation on such a route therefore cannot be
    written against an unresolved identifier, which is what keeps R6.9 out of each operation's
    hands.
    """

    operation: Operation
    principal: AuthenticatedPrincipal
    body: Mapping[str, Any]
    session: SessionRecord | None = None


@dataclass(frozen=True, slots=True)
class OperationResult:
    """What an operation returns: a status and the payload to serialise."""

    payload: Mapping[str, Any]
    status: int = HTTPStatus.OK


class SessionOperations(Protocol):
    """The eight operations, as the one interface the dispatcher knows.

    Each method is a seam. The task that fills it is named on the corresponding method of
    :class:`NotImplementedOperations`.
    """

    def create_session(self, request: OperationRequest) -> OperationResult: ...

    def resolve_session(self, request: OperationRequest) -> OperationResult: ...

    def get_session(self, request: OperationRequest) -> OperationResult: ...

    def list_sessions(self, request: OperationRequest) -> OperationResult: ...

    def suspend_session(self, request: OperationRequest) -> OperationResult: ...

    def resume_session(self, request: OperationRequest) -> OperationResult: ...

    def terminate_session(self, request: OperationRequest) -> OperationResult: ...

    def refresh_connection(self, request: OperationRequest) -> OperationResult: ...





#: Operation to method name. The dispatch table, derived from nothing and read by the dispatcher
#: alone, with the completeness check below standing in for the eight `if` branches it replaces.
OPERATION_METHODS: Final[Mapping[Operation, str]] = {
    Operation.CREATE_SESSION: "create_session",
    Operation.RESOLVE_SESSION: "resolve_session",
    Operation.GET_SESSION: "get_session",
    Operation.LIST_SESSIONS: "list_sessions",
    Operation.SUSPEND_SESSION: "suspend_session",
    Operation.RESUME_SESSION: "resume_session",
    Operation.TERMINATE_SESSION: "terminate_session",
    Operation.REFRESH_CONNECTION: "refresh_connection",
}

if set(OPERATION_METHODS) != set(Operation):  # pragma: no cover - import-time invariant
    raise AssertionError("OPERATION_METHODS does not cover every Operation")


@dataclass(frozen=True, slots=True)
class NotImplementedOperations:
    """The default implementation: every operation `501`, each naming the task that fills it.

    This exists so that the route set and the not-found response are complete and exercised before
    any operation's behaviour is. A `501` naming the operation is a true statement about a routed
    surface with nothing behind it yet; an `AttributeError` reaching the gateway as a `500` would
    not be.
    """

    def create_session(self, request: OperationRequest) -> OperationResult:
        """Validate, record, start the orchestration, wait, return.

        Steps 1 to 3 are filled by :class:`~control_plane.api.creation.CreationOperations`, which
        writes the complete Session row before any execution exists and starts the execution that
        provisions (tasks 6.2, 6.4). Step 4, the wait, reaches it through
        :class:`~control_plane.api.creation.CreationWait` (task 6.6). This seam stays here so a
        deployment that has wired no store and no state machine answers `501` rather than recording
        a Session it cannot govern.
        """
        raise OperationNotImplemented(request.operation.value)

    def resolve_session(self, request: OperationRequest) -> OperationResult:
        """Get-or-create by Affinity_Key, as one conditional transaction.

        Filled by :class:`~control_plane.api.resolution.ResolutionOperations`, whose claim is a
        single two-item transaction and whose loser branches on the bound Session's lifecycle state.
        This seam stays here so a deployment that has wired no binding store answers `501` rather
        than reading a binding it cannot write.
        """
        raise OperationNotImplemented(request.operation.value)

    def get_session(self, request: OperationRequest) -> OperationResult:
        """Report the resolved record's lifecycle state and any published credential (task 6.6)."""
        raise OperationNotImplemented(request.operation.value)

    def list_sessions(self, request: OperationRequest) -> OperationResult:
        """Query the Tenant partition through `tenant-state-index` (task 6.18)."""
        raise OperationNotImplemented(request.operation.value)

    def suspend_session(self, request: OperationRequest) -> OperationResult:
        """Provider suspend, then mirror the reported state onto the record (task 6.18)."""
        raise OperationNotImplemented(request.operation.value)

    def resume_session(self, request: OperationRequest) -> OperationResult:
        """Provider resume, then mirror the reported state onto the record (task 6.18)."""
        raise OperationNotImplemented(request.operation.value)

    def terminate_session(self, request: OperationRequest) -> OperationResult:
        """Idempotent termination, succeeding on an already terminal Session (task 6.18)."""
        raise OperationNotImplemented(request.operation.value)

    def refresh_connection(self, request: OperationRequest) -> OperationResult:
        """Mint a replacement connection credential as the sole issuer.

        Filled by :class:`~control_plane.api.connection.ConnectionOperations`, which reaches
        :class:`~control_plane.credentials.ConnectionIssuer` and adds no scoping decision of its
        own. This seam stays here so a deployment that wires no issuer answers `501` rather than
        minting nothing quietly.
        """
        raise OperationNotImplemented(request.operation.value)


@dataclass(frozen=True, slots=True)
class _NoLookup:
    """The lookup a deployment that has wired no State_Store access has.

    Present so :class:`ControlPlaneApi` can be constructed for the route-level assertions without a
    store, and so that reaching a Session-naming route in that state is a `501` from the operation
    rather than a read against nothing. It reports absence, which is the truthful answer for a
    handler with no store: there is no Session it can address.
    """

    def read_session(
        self, *, partition_key: str, sort_key: str
    ) -> Mapping[str, Any] | None:
        return None


@dataclass(frozen=True, slots=True)
class ControlPlaneApi:
    """The Control_Plane request dispatcher.

    Holds an operations implementation and the Session lookup, both injected, so the offline suite
    drives the whole path — authorization, routing, resolution, rendering — with no deployed
    resource and no network.
    """

    operations: SessionOperations = field(default_factory=NotImplementedOperations)
    lookup: SessionLookup = field(default_factory=_NoLookup)

    def handle(self, event: Mapping[str, Any]) -> HttpResponse:
        """Serve one invocation, returning the response to render.

        Ordered so that the least informative refusal comes first. Authorization precedes routing,
        because an invocation the handler cannot attribute to a principal should not learn which
        paths exist; and routing precedes resolution, because resolving an identifier requires a
        Tenant partition, which requires the principal.
        """
        try:
            principal = principal_for(event)
            matched = self._route(event)
            if matched is None:
                # An unroutable path names no Session, so the fixed not-found response is both
                # true and the least revealing thing available.
                return not_found()
            route, path_parameters = matched
            request = self._build_request(route, path_parameters, principal, event)
            result = self._invoke(request)
        except ControlPlaneError as exc:
            return exc.response
        return json_response(result.status, dict(result.payload))

    def _route(
        self, event: Mapping[str, Any]
    ) -> tuple[RouteDefinition, dict[str, str]] | None:
        method, path = request_method_and_path(event)
        return route_for(method, path)

    def _build_request(
        self,
        route: RouteDefinition,
        path_parameters: Mapping[str, str],
        principal: AuthenticatedPrincipal,
        event: Mapping[str, Any],
    ) -> OperationRequest:
        """Assemble the operation's input, resolving the Session where the route names one.

        The resolution happens here and not in the operation, so that R6.9's not-found is a property
        of the dispatcher rather than a rule each of the five Session-naming operations has to
        follow.

        It also happens *before* the body is decoded, which is deliberate: a caller who cannot
        address the named Session learns nothing about their body either, so the not-found path is
        reached identically whatever the body contains.
        """
        session: SessionRecord | None = None
        if route.names_a_session:
            session = resolve_session(
                principal, path_parameters.get(SESSION_ID_PARAMETER, ""), self.lookup
            )
        return OperationRequest(
            operation=route.operation,
            principal=principal,
            body=request_body(event),
            session=session,
        )

    def _invoke(self, request: OperationRequest) -> OperationResult:
        method: Callable[[OperationRequest], OperationResult] = getattr(
            self.operations, OPERATION_METHODS[request.operation]
        )
        return method(request)


def lambda_entrypoint(
    api: ControlPlaneApi,
) -> Callable[[Mapping[str, Any], Any], dict[str, Any]]:
    """Adapt a dispatcher to the Lambda handler signature.

    A factory rather than a module-level `lambda_handler`, because the dispatcher a deployment needs
    is built from the State_Store access wiring, and a module-level handler would have to construct
    that at import time — including for every test that only wants the routing table.
    `ControlPlaneStack` names the handler it builds from this.
    """

    def handler(event: Mapping[str, Any], context: Any) -> dict[str, Any]:
        # `context` is part of the Lambda signature and is deliberately unread: nothing on it is
        # request-attributable in a way this dispatcher should route into a response.
        del context
        return api.handle(event).to_payload()

    return handler
