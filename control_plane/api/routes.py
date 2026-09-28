# kiro-classification: public
"""The eight Control_Plane operations, their routes, and the authorization every route carries.

This is the operation table of the design's Control_Plane section, as data rather than as prose.
Three consumers read it and none of them may hold a second copy: the request dispatcher in
:mod:`control_plane.api.handlers`, which routes an incoming request onto an operation;
`ControlPlaneStack`, which synthesises one API Gateway HTTP API route per entry; and the smoke
assertion that every route carries the `AWS_IAM` authorizer (R6.3, R6.22). A route the stack
declared and the dispatcher did not know, or the reverse, is the failure mode this table removes.

**Authorization is a property of the route set, not of a route.** :data:`AUTHORIZATION_TYPE` is
one constant and every entry carries it, because R6.3 admits no exception: there is no
unauthenticated Control_Plane route, and R6.22 restates the same requirement for the one operation
that names an Affinity_Key, so the `resolve` route is authorized by the same declaration rather
than by a clause of its own. The check itself runs in API Gateway, before any code in this
repository, which is why R6.3's guarantee does not depend on the correctness of anything here.

Path parameters are matched here rather than read from the gateway's own `pathParameters`, so that
the template a route declares and the identifier a handler receives have one producer. The only
parameter any route declares is :data:`SESSION_ID_PARAMETER`; no route declares a Tenant, because
the Tenant of a request is derived from the authenticated principal alone
(:func:`control_plane.tenancy.tenant_of`) and a caller who could name one would have named their
way out of the confinement that makes cross-tenant access structurally impossible.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Final

__all__ = [
    "AUTHORIZATION_TYPE",
    "OPERATIONS_NAMING_A_SESSION",
    "ROUTES",
    "ROUTES_BY_OPERATION",
    "SESSION_ID_PARAMETER",
    "Operation",
    "RouteDefinition",
    "route_for",
    "route_for_key",
]

#: The API Gateway authorizer type every route carries. SigV4 is enforced by the service, so an
#: unsigned request is rejected before a handler is invoked (R6.3).
AUTHORIZATION_TYPE: Final = "AWS_IAM"

#: The single path parameter in the route set. `{id}` as the design spells it.
SESSION_ID_PARAMETER: Final = "id"

_PARAMETER_OPEN: Final = "{"
_PARAMETER_CLOSE: Final = "}"


class Operation(Enum):
    """The eight operations the Control_Plane exposes (R6.1).

    The value of each member is the operation name the design's table uses, which is also the name
    that appears in a lifecycle audit record and in a metric dimension, so it is written once here.
    """

    CREATE_SESSION = "CreateSession"
    RESOLVE_SESSION = "ResolveSession"
    GET_SESSION = "GetSession"
    LIST_SESSIONS = "ListSessions"
    SUSPEND_SESSION = "SuspendSession"
    RESUME_SESSION = "ResumeSession"
    TERMINATE_SESSION = "TerminateSession"
    REFRESH_CONNECTION = "RefreshConnection"


@dataclass(frozen=True, slots=True)
class RouteDefinition:
    """One operation's HTTP surface.

    `authorization_type` is a field with one possible value rather than an implied constant, so
    that the synthesised route and the smoke assertion read the same attribute instead of each
    knowing the answer separately.
    """

    operation: Operation
    method: str
    path_template: str
    authorization_type: str = AUTHORIZATION_TYPE

    @property
    def route_key(self) -> str:
        """The API Gateway HTTP API route key, `"<METHOD> <template>"`."""
        return f"{self.method} {self.path_template}"

    @property
    def parameter_names(self) -> tuple[str, ...]:
        """The path parameters this template declares, in order."""
        return tuple(
            segment[1:-1]
            for segment in _segments(self.path_template)
            if segment.startswith(_PARAMETER_OPEN)
            and segment.endswith(_PARAMETER_CLOSE)
        )

    @property
    def names_a_session(self) -> bool:
        """Whether this route carries a Session identifier in its path.

        The dispatcher resolves that identifier inside the caller's own Tenant partition before
        the operation runs, so every route for which this is true is a route on which R6.9's
        not-found response is reached without the operation having to remember it.
        """
        return SESSION_ID_PARAMETER in self.parameter_names


def _segments(path: str) -> tuple[str, ...]:
    """Split a path or template into its non-empty segments.

    Non-empty, so that a trailing slash and a doubled separator do not produce a path that matches
    nothing while looking like it should.
    """
    return tuple(segment for segment in path.split("/") if segment)


#: The operation table, in the order the design's table lists it.
ROUTES: Final[tuple[RouteDefinition, ...]] = (
    # Validate, record, start the orchestration, await the published credential (tasks 6.2-6.6).
    RouteDefinition(Operation.CREATE_SESSION, "POST", "/sessions"),
    # Get-or-create by Affinity_Key; exactly one of resolve or create (task 6.9).
    RouteDefinition(Operation.RESOLVE_SESSION, "POST", "/sessions/resolve"),
    RouteDefinition(
        Operation.GET_SESSION, "GET", f"/sessions/{{{SESSION_ID_PARAMETER}}}"
    ),
    # Tenant-partition query only; no unpartitioned read path exists.
    RouteDefinition(Operation.LIST_SESSIONS, "GET", "/sessions"),
    # Provider suspend, resume and terminate, with the state update (task 6.18).
    RouteDefinition(
        Operation.SUSPEND_SESSION,
        "POST",
        f"/sessions/{{{SESSION_ID_PARAMETER}}}/suspend",
    ),
    RouteDefinition(
        Operation.RESUME_SESSION, "POST", f"/sessions/{{{SESSION_ID_PARAMETER}}}/resume"
    ),
    RouteDefinition(
        Operation.TERMINATE_SESSION,
        "POST",
        f"/sessions/{{{SESSION_ID_PARAMETER}}}/terminate",
    ),
    # Issues a replacement connection credential (task 6.12).
    RouteDefinition(
        Operation.REFRESH_CONNECTION,
        "POST",
        f"/sessions/{{{SESSION_ID_PARAMETER}}}/connection",
    ),
)

ROUTES_BY_OPERATION: Final[dict[Operation, RouteDefinition]] = {
    route.operation: route for route in ROUTES
}

#: The operations whose path carries a Session identifier. Derived rather than listed, so it cannot
#: fall out of step with the templates above.
OPERATIONS_NAMING_A_SESSION: Final[frozenset[Operation]] = frozenset(
    route.operation for route in ROUTES if route.names_a_session
)

# Every operation is routed and every route is an operation. Asserted at import rather than only in
# the suite, because a table with a missing entry is a route the stack would synthesise onto a
# dispatcher that cannot serve it.
if len(ROUTES_BY_OPERATION) != len(
    Operation
):  # pragma: no cover - import-time invariant
    missing = sorted(
        operation.value
        for operation in Operation
        if operation not in ROUTES_BY_OPERATION
    )
    raise AssertionError(f"operations with no route: {', '.join(missing)}")


def route_for_key(route_key: str) -> RouteDefinition | None:
    """Return the route with this API Gateway route key, or `None`.

    Exact rather than pattern-matched, because a route key is the template the gateway itself
    matched, not a request path.
    """
    for route in ROUTES:
        if route.route_key == route_key:
            return route
    return None


def route_for(method: str, path: str) -> tuple[RouteDefinition, dict[str, str]] | None:
    """Match a request method and raw path onto a route and its path parameters.

    Literal routes are tried before parameterised ones, so `POST /sessions/resolve` matches the
    resolve operation rather than being captured as an identifier by a template that happens to
    have the same shape. The order is a property of this function rather than of the order entries
    happen to appear in :data:`ROUTES`.

    Returns `None` when nothing matches. The caller maps that to the same fixed not-found response
    an unknown Session gets: an unroutable path names no Session, so there is nothing else true to
    say about it, and one fewer distinguishable response is one fewer thing to measure.
    """
    upper_method = method.upper()
    candidates = _segments(path)
    for parameterised in (False, True):
        for route in ROUTES:
            if route.method != upper_method:
                continue
            if bool(route.parameter_names) is not parameterised:
                continue
            captured = _match_segments(_segments(route.path_template), candidates)
            if captured is not None:
                return route, captured
    return None


def _match_segments(
    template: tuple[str, ...], candidate: tuple[str, ...]
) -> dict[str, str] | None:
    """Match one path against one template, returning the captured parameters.

    A parameter never captures an empty segment: `_segments` has already dropped empty ones, so a
    request for `/sessions//suspend` has two segments and matches nothing rather than binding the
    identifier to the empty string, which would reach the State_Store as a malformed sort key.
    """
    if len(template) != len(candidate):
        return None
    captured: dict[str, str] = {}
    for template_segment, candidate_segment in zip(template, candidate, strict=True):
        if template_segment.startswith(_PARAMETER_OPEN) and template_segment.endswith(
            _PARAMETER_CLOSE
        ):
            captured[template_segment[1:-1]] = candidate_segment
        elif template_segment != candidate_segment:
            return None
    return captured
