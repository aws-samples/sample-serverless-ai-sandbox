# kiro-classification: public
"""The eight operations, the `AWS_IAM` route set, and the fixed not-found response.

Every assertion here is deterministic. Phase 6's properties belong to their own tasks — Property 11
to admission validation, Property 13 to Tenant partition confinement — so nothing in this file draws
inputs; the cross-tenant case is stated as the two specific requests R6.9 names.

The central test is `test_a_cross_tenant_identifier_and_a_never_existed_one_are_byte_identical`. It
is an information-disclosure assertion, not a formatting one: if it fails, the Control_Plane is an
oracle for whether another Tenant's Session exists.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from http import HTTPStatus
from typing import Any

import pytest

from control_plane.api import (
    AUTHORIZATION_TYPE,
    NOT_FOUND_BODY,
    NOT_FOUND_RESPONSE,
    OPERATION_METHODS,
    OPERATIONS_NAMING_A_SESSION,
    ROUTES,
    ROUTES_BY_OPERATION,
    ControlPlaneApi,
    Operation,
    OperationRequest,
    OperationResult,
    SessionNotFound,
    lambda_entrypoint,
    resolve_session,
    route_for,
    route_for_key,
)
from control_plane.state.records import LifecycleState, SessionRecord
from control_plane.tenancy import (
    DEPLOYMENT_PROFILE_VARIABLE,
    TENANT_ID_VARIABLE,
    AuthenticatedPrincipal,
    DeploymentProfile,
    pk_for,
    reset_resolver_cache,
)

TENANT_A = "tenant-a"
TENANT_B = "tenant-b"

CALLER_A = f"arn:aws:sts::123456789012:assumed-role/Caller/{TENANT_A}"
CALLER_B = f"arn:aws:sts::123456789012:assumed-role/Caller/{TENANT_B}"

#: A well-formed identifier that exists, in Tenant B's partition.
SESSION_OF_B = "01JCROSSTENANTAAAAAAAAAAAA"

#: A well-formed identifier that was never created anywhere.
NEVER_EXISTED = "01JNEVEREXISTEDBBBBBBBBBBB"

SESSION_OF_A = "01JOWNSESSIONCCCCCCCCCCCCC"


@pytest.fixture(autouse=True)
def _forget_the_held_resolver(monkeypatch: pytest.MonkeyPatch) -> None:
    """Run under `multi-tenant`, because two principals must resolve to two Tenants.

    Under `single-tenant` both callers below would resolve to one Tenant and the cross-tenant case
    would be unexpressible, which is exactly the reason the design closes the deployed half of this
    assertion with a second deployment rather than with the demonstration.
    """
    monkeypatch.setenv(
        DEPLOYMENT_PROFILE_VARIABLE, DeploymentProfile.MULTI_TENANT.value
    )
    monkeypatch.delenv(TENANT_ID_VARIABLE, raising=False)
    reset_resolver_cache()


def principal(tenant_id: str, caller_identity: str) -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(caller_identity=caller_identity, tenant_id=tenant_id)


def session_record(tenant_id: str, session_id: str) -> SessionRecord:
    """A complete Session row in one Tenant's partition.

    The partition key comes from `pk_for` because that is the only producer of one; a test that
    spelled the prefix itself would be a second producer and the lint rule would reject it.
    """
    return SessionRecord(
        pk=pk_for(principal(tenant_id, f"arn:aws:sts::1:assumed-role/x/{tenant_id}")),
        session_id=session_id,
        tenant_id=tenant_id,
        provider_name="local-firecracker",
        lifecycle_state=LifecycleState.RUNNING,
        created_at=1_760_000_000,
        updated_at=1_760_000_000,
        max_duration_seconds=3600,
        idle_seconds=300,
        suspended_seconds=600,
        auto_resume=True,
        memory_bytes=512 * 1024 * 1024,
        execution_role_arn="arn:aws:iam::123456789012:role/SandboxExecution",
        reap_shard=3,
        reap_deadline=1_760_003_600,
        artifact_retention_days=7,
    )


@dataclass
class FakeStore:
    """An in-memory State_Store keyed exactly as DynamoDB is: partition key, then sort key.

    Faithful in the one respect that matters here — a `GetItem` naming a partition key the item does
    not carry finds nothing — which is how a real read against `pk_for(caller)` fails to see another
    Tenant's row. No network, no deployed resource.
    """

    items: dict[tuple[str, str], Mapping[str, Any]] = field(default_factory=dict)
    reads: list[tuple[str, str]] = field(default_factory=list)

    def put(self, record: SessionRecord) -> None:
        item = record.to_item()
        self.items[(record.pk, record.sort_key)] = item

    def read_session(
        self, *, partition_key: str, sort_key: str
    ) -> Mapping[str, Any] | None:
        self.reads.append((partition_key, sort_key))
        return self.items.get((partition_key, sort_key))


@dataclass
class RecordingOperations:
    """A `SessionOperations` that records what it was handed and returns a fixed result."""

    seen: list[OperationRequest] = field(default_factory=list)

    def _accept(self, request: OperationRequest) -> OperationResult:
        self.seen.append(request)
        return OperationResult(payload={"operation": request.operation.value})

    create_session = _accept
    resolve_session = _accept
    get_session = _accept
    list_sessions = _accept
    suspend_session = _accept
    resume_session = _accept
    terminate_session = _accept
    refresh_connection = _accept


def event(
    method: str,
    path: str,
    *,
    caller_identity: str | None = CALLER_A,
    tenant_id: str | None = TENANT_A,
    body: str | None = None,
) -> dict[str, Any]:
    """An API Gateway HTTP API payload-format-2.0 invocation.

    The identity lives under `requestContext.authorizer`, which API Gateway populates and no caller
    can set. There is deliberately no way to express a Tenant anywhere else in this helper.
    """
    authorizer: dict[str, Any] = {}
    if caller_identity is not None:
        authorizer["iam"] = {"userArn": caller_identity}
    if tenant_id is not None:
        authorizer["tenantId"] = tenant_id
    return {
        "version": "2.0",
        "rawPath": path,
        "requestContext": {"http": {"method": method}, "authorizer": authorizer},
        "body": body,
        "isBase64Encoded": False,
    }


def api(store: FakeStore | None = None, operations: Any = None) -> ControlPlaneApi:
    resolved = store if store is not None else FakeStore()
    if operations is None:
        return ControlPlaneApi(lookup=resolved)
    return ControlPlaneApi(operations=operations, lookup=resolved)


# --- The eight operations and their routes (R6.1) -----------------------------------------------


def test_there_are_exactly_eight_operations_with_the_designed_routes() -> None:
    assert len(Operation) == 8
    assert {route.route_key for route in ROUTES} == {
        "POST /sessions",
        "POST /sessions/resolve",
        "GET /sessions/{id}",
        "GET /sessions",
        "POST /sessions/{id}/suspend",
        "POST /sessions/{id}/resume",
        "POST /sessions/{id}/terminate",
        "POST /sessions/{id}/connection",
    }


def test_every_operation_has_exactly_one_route_and_one_dispatch_entry() -> None:
    assert set(ROUTES_BY_OPERATION) == set(Operation)
    assert set(OPERATION_METHODS) == set(Operation)
    assert len(ROUTES) == len(Operation)


def test_five_operations_name_a_session_in_their_path() -> None:
    # The five on which R6.9's not-found is reachable; create, resolve and list name none.
    assert OPERATIONS_NAMING_A_SESSION == {
        Operation.GET_SESSION,
        Operation.SUSPEND_SESSION,
        Operation.RESUME_SESSION,
        Operation.TERMINATE_SESSION,
        Operation.REFRESH_CONNECTION,
    }


def test_no_route_declares_a_tenant_parameter() -> None:
    # The Tenant comes from the authenticated principal alone; a caller who could name one would
    # have named their way out of the confinement (R11.17, R11.18).
    for route in ROUTES:
        assert route.parameter_names in ((), ("id",))
        assert "tenant" not in route.path_template.lower()


# --- Authorization (R6.3, R6.22) ----------------------------------------------------------------


def test_every_route_carries_the_aws_iam_authorizer() -> None:
    assert AUTHORIZATION_TYPE == "AWS_IAM"
    assert {route.authorization_type for route in ROUTES} == {"AWS_IAM"}


def test_the_affinity_key_route_is_authorized_by_the_same_declaration() -> None:
    # R6.22 is not a clause of its own: the resolve route is in the same authorized set.
    resolve = ROUTES_BY_OPERATION[Operation.RESOLVE_SESSION]
    assert resolve.route_key == "POST /sessions/resolve"
    assert resolve.authorization_type == AUTHORIZATION_TYPE


def test_an_invocation_with_no_verified_caller_is_refused_before_routing() -> None:
    response = api().handle(event("GET", "/sessions", caller_identity=None))
    assert response.status == HTTPStatus.FORBIDDEN
    # Refused before routing, so it learns nothing about which paths exist.
    assert response is api().handle(event("GET", "/nonexistent", caller_identity=None))


def test_a_multi_tenant_invocation_with_no_tenant_attribute_is_refused() -> None:
    response = api().handle(event("GET", "/sessions", tenant_id=None))
    assert response.status == HTTPStatus.FORBIDDEN


def test_an_authorized_invocation_reaches_its_operation_with_the_resolved_tenant() -> (
    None
):
    operations = RecordingOperations()
    response = api(operations=operations).handle(event("GET", "/sessions"))
    assert response.status == HTTPStatus.OK
    assert [request.operation for request in operations.seen] == [
        Operation.LIST_SESSIONS
    ]
    assert operations.seen[0].principal.tenant_id == TENANT_A


# --- Routing --------------------------------------------------------------------------------


def test_a_literal_route_wins_over_a_parameterised_one() -> None:
    matched = route_for("POST", "/sessions/resolve")
    assert matched is not None
    route, parameters = matched
    assert route.operation is Operation.RESOLVE_SESSION
    assert parameters == {}


@pytest.mark.parametrize(
    ("method", "path", "operation"),
    [
        ("POST", "/sessions", Operation.CREATE_SESSION),
        ("GET", "/sessions", Operation.LIST_SESSIONS),
        ("GET", f"/sessions/{SESSION_OF_A}", Operation.GET_SESSION),
        ("POST", f"/sessions/{SESSION_OF_A}/suspend", Operation.SUSPEND_SESSION),
        ("POST", f"/sessions/{SESSION_OF_A}/resume", Operation.RESUME_SESSION),
        ("POST", f"/sessions/{SESSION_OF_A}/terminate", Operation.TERMINATE_SESSION),
        ("POST", f"/sessions/{SESSION_OF_A}/connection", Operation.REFRESH_CONNECTION),
    ],
)
def test_each_route_matches_its_operation(
    method: str, path: str, operation: Operation
) -> None:
    matched = route_for(method, path)
    assert matched is not None
    assert matched[0].operation is operation


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("DELETE", "/sessions"),
        ("GET", "/sessions/a/suspend"),
        ("POST", "/sessions/a/unknown"),
        ("GET", "/"),
        ("GET", ""),
        ("POST", "/sessions//suspend"),
    ],
)
def test_an_unroutable_request_matches_nothing(method: str, path: str) -> None:
    assert route_for(method, path) is None


def test_route_for_key_is_exact() -> None:
    assert route_for_key("POST /sessions/resolve") is not None
    assert route_for_key("POST /sessions/anything/suspend") is None


# --- The fixed not-found response (R6.9, R6.22) -------------------------------------------------


def test_the_not_found_body_echoes_no_identifier() -> None:
    for secret in (SESSION_OF_A, SESSION_OF_B, NEVER_EXISTED, TENANT_A, TENANT_B):
        assert secret.encode() not in NOT_FOUND_BODY
    # Nothing derived from a request: no tenant word, no request identifier, no reason code.
    assert b"tenant" not in NOT_FOUND_BODY.lower()
    assert b"request" not in NOT_FOUND_BODY.lower()


def test_not_found_is_one_shared_constant_rather_than_a_builder() -> None:
    first = SessionNotFound().response
    second = SessionNotFound().response
    # Identity, not equality: two raisers cannot produce two different responses.
    assert first is second is NOT_FOUND_RESPONSE


def test_a_cross_tenant_identifier_and_a_never_existed_one_are_byte_identical() -> None:
    """R6.9's assertion, over the response bytes rather than over the status alone.

    Tenant B owns a Session. Tenant A asks for it by identifier, and separately asks for an
    identifier that was never created. The two responses must be indistinguishable in status, in
    headers and in body, or the Control_Plane answers "does another Tenant hold this Session?".
    """
    store = FakeStore()
    store.put(session_record(TENANT_B, SESSION_OF_B))
    dispatcher = api(store)

    cross_tenant = dispatcher.handle(
        event(
            "GET",
            f"/sessions/{SESSION_OF_B}",
            caller_identity=CALLER_A,
            tenant_id=TENANT_A,
        )
    )
    never_existed = dispatcher.handle(
        event(
            "GET",
            f"/sessions/{NEVER_EXISTED}",
            caller_identity=CALLER_A,
            tenant_id=TENANT_A,
        )
    )

    assert cross_tenant.to_bytes() == never_existed.to_bytes()
    assert cross_tenant.status == HTTPStatus.NOT_FOUND
    assert cross_tenant.headers == never_existed.headers
    assert cross_tenant.body == NOT_FOUND_BODY
    # The rendered gateway payload too, so a difference cannot hide in the rendering step.
    assert cross_tenant.to_payload() == never_existed.to_payload()

    # And Tenant B really does hold that Session: the test above would pass vacuously otherwise.
    assert (
        dispatcher.handle(
            event(
                "GET",
                f"/sessions/{SESSION_OF_B}",
                caller_identity=CALLER_B,
                tenant_id=TENANT_B,
            )
        ).status
        == HTTPStatus.NOT_IMPLEMENTED
    )


def test_both_reads_are_the_same_operation_against_the_callers_own_partition() -> None:
    """There is no second code path whose timing or logging could differ.

    Layer 3's claim is that the two cases are one failed `GetItem` each, against the caller's own
    partition. That is checkable: both reads carry the *same* partition key — Tenant A's — and
    differ only in the sort key built from the identifier.
    """
    store = FakeStore()
    store.put(session_record(TENANT_B, SESSION_OF_B))
    dispatcher = api(store)
    for identifier in (SESSION_OF_B, NEVER_EXISTED):
        dispatcher.handle(event("GET", f"/sessions/{identifier}"))

    partition_keys = {partition for partition, _ in store.reads}
    assert partition_keys == {pk_for(principal(TENANT_A, CALLER_A))}
    assert len(store.reads) == 2
    assert store.reads[0][1] != store.reads[1][1]


@pytest.mark.parametrize(
    "identifier",
    [
        NEVER_EXISTED,
        SESSION_OF_B,
        # Malformed: carries the key separator, so it cannot name any Session. Answered the same
        # way rather than with a 400, which would hand a prober one bit for free.
        "S#forged",
        "with#separator",
    ],
)
def test_every_unaddressable_identifier_gets_the_identical_response(
    identifier: str,
) -> None:
    store = FakeStore()
    store.put(session_record(TENANT_B, SESSION_OF_B))
    response = api(store).handle(event("GET", f"/sessions/{identifier}"))
    assert response is NOT_FOUND_RESPONSE


def test_an_unroutable_path_gets_the_same_fixed_response() -> None:
    # One fewer distinguishable body than a bespoke 404 or a 405 would be.
    assert api().handle(event("GET", "/sessions/a/b/c")) is NOT_FOUND_RESPONSE


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", f"/sessions/{NEVER_EXISTED}"),
        ("POST", f"/sessions/{NEVER_EXISTED}/suspend"),
        ("POST", f"/sessions/{NEVER_EXISTED}/resume"),
        ("POST", f"/sessions/{NEVER_EXISTED}/terminate"),
        ("POST", f"/sessions/{NEVER_EXISTED}/connection"),
    ],
)
def test_not_found_is_reached_on_every_session_naming_route(
    method: str, path: str
) -> None:
    """Resolution happens in the dispatcher, so no operation can forget it.

    `RecordingOperations` accepts everything; if resolution were the operation's job, these would
    return 200.
    """
    operations = RecordingOperations()
    response = api(operations=operations).handle(event(method, path))
    assert response is NOT_FOUND_RESPONSE
    assert operations.seen == []


def test_resolve_session_hands_the_record_to_the_operation() -> None:
    store = FakeStore()
    store.put(session_record(TENANT_A, SESSION_OF_A))
    operations = RecordingOperations()
    response = api(store, operations).handle(event("GET", f"/sessions/{SESSION_OF_A}"))
    assert response.status == HTTPStatus.OK
    assert operations.seen[0].session is not None
    assert operations.seen[0].session.session_id == SESSION_OF_A


def test_resolve_session_raises_rather_than_comparing_tenants() -> None:
    store = FakeStore()
    store.put(session_record(TENANT_B, SESSION_OF_B))
    with pytest.raises(SessionNotFound):
        resolve_session(principal(TENANT_A, CALLER_A), SESSION_OF_B, store)


# --- The seams the later tasks fill in ----------------------------------------------------------


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", "/sessions"),
        ("POST", "/sessions/resolve"),
        ("GET", "/sessions"),
    ],
)
def test_an_unimplemented_operation_is_a_501_naming_it(method: str, path: str) -> None:
    response = api().handle(event(method, path))
    assert response.status == HTTPStatus.NOT_IMPLEMENTED
    matched = route_for(method, path)
    assert matched is not None
    assert matched[0].operation.value.encode() in response.body


def test_every_operation_has_a_seam_on_the_default_implementation() -> None:
    dispatcher = ControlPlaneApi()
    for method_name in OPERATION_METHODS.values():
        assert callable(getattr(dispatcher.operations, method_name))


# --- Request reading ---------------------------------------------------------------------------


@pytest.mark.parametrize("body", [None, "", '{"durationSeconds":60}'])
def test_an_absent_or_object_body_is_accepted(body: str | None) -> None:
    operations = RecordingOperations()
    response = api(operations=operations).handle(event("POST", "/sessions", body=body))
    assert response.status == HTTPStatus.OK
    assert isinstance(operations.seen[0].body, Mapping)


@pytest.mark.parametrize("body", ["[1,2]", "not json", '"a string"', "7"])
def test_a_body_that_is_not_a_json_object_is_a_400(body: str) -> None:
    response = api().handle(event("POST", "/sessions", body=body))
    assert response.status == HTTPStatus.BAD_REQUEST


def test_a_base64_body_is_decoded() -> None:
    import base64

    invocation = event("POST", "/sessions", body=base64.b64encode(b'{"a":1}').decode())
    invocation["isBase64Encoded"] = True
    operations = RecordingOperations()
    response = api(operations=operations).handle(invocation)
    assert response.status == HTTPStatus.OK
    assert operations.seen[0].body == {"a": 1}


# --- The Lambda adapter -------------------------------------------------------------------------


def test_the_lambda_entrypoint_renders_the_gateway_payload() -> None:
    handler = lambda_entrypoint(api())
    payload = handler(event("GET", f"/sessions/{NEVER_EXISTED}"), None)
    assert payload == {
        "statusCode": 404,
        "headers": {"content-type": "application/json", "cache-control": "no-store"},
        "body": NOT_FOUND_BODY.decode(),
        "isBase64Encoded": False,
    }


def test_a_malformed_body_does_not_change_the_not_found_response() -> None:
    """Resolution precedes body decoding, so the 404 path is uniform whatever the body says."""
    store = FakeStore()
    store.put(session_record(TENANT_B, SESSION_OF_B))
    dispatcher = api(store)
    for body in (None, "not json", "[1,2]", '{"durationSeconds":60}'):
        for identifier in (SESSION_OF_B, NEVER_EXISTED):
            response = dispatcher.handle(
                event("POST", f"/sessions/{identifier}/terminate", body=body)
            )
            assert response is NOT_FOUND_RESPONSE
