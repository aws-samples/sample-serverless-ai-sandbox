# kiro-classification: public
"""Connection credential issuance: one issuer, one scope derivation, one clamp.

Every assertion here is deterministic. Property 15 — credential scoping and expiry over drawn port
sets and drawn Session remainders — is task 6.13 and belongs to its own file, so nothing here draws
inputs.

The tests that matter are the structural ones, and they are structural in three different senses:

- `test_issue_takes_the_record_and_nothing_else` reads the entry point's signature. There is no
  `ports` parameter and no `ttl_seconds` parameter, so a caller cannot widen a credential's reach.
  That is the whole of "sole issuer" as this repository can enforce it in Python.
- `test_the_issuer_is_the_sole_caller_of_the_mint_in_the_repository` runs the lint rule over the
  tree. A second call site fails the build.
- `test_the_control_port_agrees_with_the_port_the_runtime_binds` compares the two spellings of the
  control port across a boundary neither side can import across.

The rest establish the scoping and clamp rules R11.4 and R11.5 fix, and that the refresh route
carries them without adding a decision of its own.
"""

from __future__ import annotations

import inspect
import textwrap
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from typing import Any

import pytest

from ci.lint_rules import sole_credential_issuer as rule
from control_plane.api import ControlPlaneApi
from control_plane.api.connection import ConnectionOperations, connection_payload
from control_plane.credentials import (
    DEFAULT_CREDENTIAL_TTL_SECONDS,
    SANDBOX_PROTOCOL_CONTROL_PORT,
    ConnectionIssuer,
    ConnectionMint,
    ConnectionNotIssuable,
    CredentialPolicy,
    RegisteredProviderMint,
)
from control_plane.providers.base import ConnectionDescriptor as MintedConnection
from control_plane.providers.base import SandboxHandle
from control_plane.state.keys import ItemShapeError
from control_plane.state.records import LifecycleState, SessionRecord
from control_plane.tenancy import (
    DEPLOYMENT_PROFILE_VARIABLE,
    TENANT_ID_VARIABLE,
    AuthenticatedPrincipal,
    DeploymentProfile,
    pk_for,
    reset_resolver_cache,
)

TENANT = "tenant-a"
CALLER = f"arn:aws:sts::123456789012:assumed-role/Caller/{TENANT}"
SESSION_ID = "01JCONNECTIONAAAAAAAAAAAAA"

#: An obviously-fake token. Nothing in this suite carries a real credential, and the shape of a
#: real one is the endpoint's business rather than this module's (R5.6).
FAKE_TOKEN = "fake-endpoint-token-for-tests"  # nosec B105 — test fixture
FAKE_BASE_URL = "https://sandbox.invalid"
AUTH_HEADER = "X-aws-proxy-auth"

#: Epoch milliseconds, the unit the Session record stores. Fixed, so every expectation below is
#: arithmetic rather than a comparison against the wall clock.
CREATED_AT_MS = 1_700_000_000_000
NOW = datetime.fromtimestamp(CREATED_AT_MS / 1000, tz=UTC)


@pytest.fixture(autouse=True)
def _fixed_tenant(monkeypatch: pytest.MonkeyPatch) -> None:
    """One Tenant, resolved from the deployment rather than from a request."""
    monkeypatch.setenv(
        DEPLOYMENT_PROFILE_VARIABLE, DeploymentProfile.SINGLE_TENANT.value
    )
    monkeypatch.setenv(TENANT_ID_VARIABLE, TENANT)
    reset_resolver_cache()


def principal() -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(caller_identity=CALLER, tenant_id=TENANT)


def session_record(
    *,
    exposed_ports: tuple[int, ...] = (),
    lifecycle_state: LifecycleState = LifecycleState.RUNNING,
    max_duration_seconds: int = 3600,
    with_handle: bool = True,
    sandbox_handle: Mapping[str, Any] | None = None,
    generation: int = 1,
) -> SessionRecord:
    """A Session row in this Tenant's partition, with the fields issuance reads."""
    handle: Mapping[str, Any] | None = None
    if sandbox_handle is not None:
        handle = sandbox_handle
    elif with_handle:
        handle = {
            "providerName": "local-firecracker",
            "sandboxId": "sandbox-1",
            "opaque": {"vm": "1"},
        }
    return SessionRecord(
        pk=pk_for(principal()),
        session_id=SESSION_ID,
        tenant_id=TENANT,
        provider_name="local-firecracker",
        lifecycle_state=lifecycle_state,
        created_at=CREATED_AT_MS,
        updated_at=CREATED_AT_MS,
        max_duration_seconds=max_duration_seconds,
        idle_seconds=300,
        suspended_seconds=600,
        auto_resume=True,
        memory_bytes=512 * 1024 * 1024,
        execution_role_arn="arn:aws:iam::123456789012:role/SandboxExecution",
        reap_shard=3,
        reap_deadline=CREATED_AT_MS + max_duration_seconds * 1000,
        artifact_retention_days=7,
        exposed_ports=exposed_ports,
        generation=generation,
        sandbox_handle=handle,
    )


@dataclass
class RecordingMint:
    """A `ConnectionMint` that records what it was asked for and mints exactly that.

    Faithful in the respect that matters: it honours the port set and the TTL it was given, so a
    test asserting the scope is asserting what the issuer decided rather than what a double chose.
    """

    calls: list[tuple[SandboxHandle, tuple[int, ...], int]] = field(
        default_factory=list
    )
    now: datetime = NOW
    #: Set to widen the minted port set or lengthen the expiry, for the belt-and-braces checks.
    override_ports: tuple[int, ...] | None = None
    expiry_overshoot: timedelta = timedelta()

    def issue_connection(
        self, handle: SandboxHandle, ports: tuple[int, ...], ttl_seconds: int
    ) -> MintedConnection:
        self.calls.append((handle, ports, ttl_seconds))
        return MintedConnection(
            base_url=FAKE_BASE_URL,
            auth_header_name=AUTH_HEADER,
            auth_header_value=FAKE_TOKEN,
            ports=self.override_ports if self.override_ports is not None else ports,
            expires_at=self.now
            + timedelta(seconds=ttl_seconds)
            + self.expiry_overshoot,
        )


def issuer(
    mint: RecordingMint | None = None,
    *,
    policy: CredentialPolicy | None = None,
    now: datetime = NOW,
) -> ConnectionIssuer:
    return ConnectionIssuer(
        mint=mint if mint is not None else RecordingMint(now=now),
        policy=policy if policy is not None else CredentialPolicy(),
        clock=lambda: now,
    )


# --- The one entry point (R6.2) ------------------------------------------------------------


def test_issue_takes_the_record_and_nothing_else() -> None:
    """The structural half of "sole issuer": there is no argument that could widen a credential.

    A `ports` or `ttl_seconds` parameter here would make every call site a co-author of the scope,
    which is exactly the shape R11.4 and R11.5 have to exclude.
    """
    parameters = list(
        inspect.signature(ConnectionIssuer.issue, eval_str=True).parameters.values()
    )
    assert [parameter.name for parameter in parameters] == ["self", "record"]
    assert parameters[1].annotation is SessionRecord
    assert parameters[1].default is inspect.Parameter.empty


def test_the_issuer_exports_no_scope_or_ttl_helper() -> None:
    """No public helper two call sites could each reimplement the derivation through."""
    from control_plane import credentials

    public = {name for name in credentials.__all__}
    assert not {name for name in public if "port_set" in name or "ttl_second" in name}
    # The derivations exist, and they are private to the issuer.
    assert hasattr(ConnectionIssuer, "_port_set")
    assert hasattr(ConnectionIssuer, "_ttl_seconds")


def test_the_mint_seam_is_one_method() -> None:
    """`ConnectionMint` is the phase 12 seam, in `PortRouting`'s shape: port in, credential out."""
    declared = {
        name
        for name in vars(ConnectionMint)
        if not name.startswith("_") or name == "issue_connection"
    }
    assert declared == {"issue_connection"}


def test_the_registered_provider_mint_selects_by_the_handle() -> None:
    """The deployment wiring adds no parameter, so it adds no way to choose a different scope."""
    parameters = list(
        inspect.signature(RegisteredProviderMint.issue_connection).parameters
    )
    assert parameters == ["self", "handle", "ports", "ttl_seconds"]
    with pytest.raises(LookupError):
        # No provider is registered in the offline suite, and the failure names the handle's
        # provider rather than falling back to some default mint.
        RegisteredProviderMint().issue_connection(
            SandboxHandle(provider_name="unregistered", sandbox_id="s", opaque={}),
            (SANDBOX_PROTOCOL_CONTROL_PORT,),
            60,
        )


# --- Port scoping (R11.4) -----------------------------------------------------------------


def test_a_session_that_declared_no_ports_gets_the_control_port_alone() -> None:
    mint = RecordingMint()
    connection = issuer(mint).issue(session_record())
    assert connection.ports == (SANDBOX_PROTOCOL_CONTROL_PORT,)
    assert mint.calls[0][1] == (SANDBOX_PROTOCOL_CONTROL_PORT,)


def test_the_port_set_is_the_declared_ports_together_with_the_control_port() -> None:
    mint = RecordingMint()
    connection = issuer(mint).issue(session_record(exposed_ports=(3000, 8080)))
    assert connection.ports == (3000, SANDBOX_PROTOCOL_CONTROL_PORT, 8080)


def test_the_port_set_is_deduplicated_and_sorted() -> None:
    """A Session may legally declare the control port, and a repeated port says nothing extra."""
    record = session_record(
        exposed_ports=(8080, 3000, 8080, SANDBOX_PROTOCOL_CONTROL_PORT)
    )
    assert issuer().issue(record).ports == (3000, SANDBOX_PROTOCOL_CONTROL_PORT, 8080)


def test_no_port_outside_the_declared_set_and_the_control_port_is_scoped() -> None:
    """The regression this guards: a credential reaching a port the Session never declared.

    `runtime.ports` refuses `port.expose` for an undeclared port on the strength of this, so a
    widened set here would make that refusal a lie.
    """
    declared = (3000, 8080)
    ports = set(issuer().issue(session_record(exposed_ports=declared)).ports)
    assert ports == {*declared, SANDBOX_PROTOCOL_CONTROL_PORT}
    assert 9000 not in ports


def test_the_credential_names_exactly_one_sandbox() -> None:
    mint = RecordingMint()
    issuer(mint).issue(session_record())
    assert len(mint.calls) == 1
    handle = mint.calls[0][0]
    assert handle.sandbox_id == "sandbox-1"
    assert handle.provider_name == "local-firecracker"


def test_the_control_port_agrees_with_the_port_the_runtime_binds() -> None:
    """Two spellings across a deployment boundary, asserted to be one number.

    The Control_Plane cannot import the runtime and the runtime cannot import the Control_Plane, so
    nothing but this assertion keeps them in step — and a credential scoped to a port the runtime
    does not serve would authenticate against nothing.
    """
    from runtime.server import DEFAULT_PORT

    assert SANDBOX_PROTOCOL_CONTROL_PORT == DEFAULT_PORT


# --- Expiry and the TTL clamp (R11.5) -----------------------------------------------------


def test_the_configured_lifetime_applies_when_the_session_remainder_exceeds_it() -> (
    None
):
    mint = RecordingMint()
    issuer(mint).issue(session_record(max_duration_seconds=3600))
    assert mint.calls[0][2] == DEFAULT_CREDENTIAL_TTL_SECONDS


def test_the_session_remainder_clamps_the_lifetime_when_it_is_shorter() -> None:
    """The clamp, in the direction that matters: a credential cannot outlive its Session.

    A credential that did would address a Sandbox that may already have been reaped and whose
    identifier may have been reused.
    """
    mint = RecordingMint()
    issuer(mint).issue(session_record(max_duration_seconds=120))
    assert mint.calls[0][2] == 120
    assert mint.calls[0][2] < DEFAULT_CREDENTIAL_TTL_SECONDS


def test_the_clamp_uses_the_remainder_rather_than_the_whole_duration() -> None:
    """Elapsed time counts. Halfway through a 1,000 s Session, 500 s remain, not 1,000."""
    mint = RecordingMint(now=NOW + timedelta(seconds=500))
    ConnectionIssuer(
        mint=mint,
        policy=CredentialPolicy(),
        clock=lambda: NOW + timedelta(seconds=500),
    ).issue(session_record(max_duration_seconds=1000))
    assert mint.calls[0][2] == 500


def test_the_remainder_is_floored_rather_than_rounded_up() -> None:
    """Half a second short of a whole second is the shorter number, never the longer one."""
    now = NOW + timedelta(milliseconds=500)
    mint = RecordingMint(now=now)
    ConnectionIssuer(mint=mint, policy=CredentialPolicy(), clock=lambda: now).issue(
        session_record(max_duration_seconds=10)
    )
    assert mint.calls[0][2] == 9


def test_the_expiry_is_carried_on_the_descriptor() -> None:
    connection = issuer().issue(session_record(max_duration_seconds=120))
    assert connection.expires_at == (NOW + timedelta(seconds=120)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def test_a_session_past_its_deadline_admits_no_credential() -> None:
    """There is no positive lifetime to issue, so nothing is minted rather than a stale credential."""
    mint = RecordingMint()
    expired = NOW + timedelta(seconds=3601)
    with pytest.raises(ConnectionNotIssuable) as raised:
        ConnectionIssuer(
            mint=mint, policy=CredentialPolicy(), clock=lambda: expired
        ).issue(session_record(max_duration_seconds=3600))
    assert "maximum duration has elapsed" in raised.value.reason
    assert mint.calls == []


def test_a_configured_lifetime_must_be_positive() -> None:
    with pytest.raises(ValueError, match="ttl_seconds"):
        CredentialPolicy(ttl_seconds=0)


def test_a_naive_clock_is_refused_rather_than_assumed_to_be_utc() -> None:
    mint = RecordingMint()
    with pytest.raises(ValueError, match="aware datetime"):
        ConnectionIssuer(
            mint=mint,
            policy=CredentialPolicy(),
            clock=lambda: datetime(2024, 1, 1, 0, 0, 0),  # noqa: DTZ001 - the case under test
        ).issue(session_record())


# --- Sessions that admit no credential ----------------------------------------------------


@pytest.mark.parametrize("state", [LifecycleState.TERMINATED, LifecycleState.FAILED])
def test_a_terminal_session_admits_no_credential(state: LifecycleState) -> None:
    mint = RecordingMint()
    with pytest.raises(ConnectionNotIssuable) as raised:
        issuer(mint).issue(session_record(lifecycle_state=state))
    assert state.value in raised.value.reason
    assert mint.calls == []


def test_a_session_with_no_sandbox_yet_admits_no_credential() -> None:
    mint = RecordingMint()
    with pytest.raises(ConnectionNotIssuable) as raised:
        issuer(mint).issue(
            session_record(lifecycle_state=LifecycleState.PENDING, with_handle=False)
        )
    assert "no Sandbox is provisioned" in raised.value.reason
    assert mint.calls == []


def test_a_suspended_session_is_served() -> None:
    """R6.20: the first request delivered to the endpoint resumes it, so a credential is issued."""
    connection = issuer().issue(
        session_record(lifecycle_state=LifecycleState.SUSPENDED)
    )
    assert connection.auth_header_value == FAKE_TOKEN


@pytest.mark.parametrize(
    "handle",
    [
        {"sandboxId": "sandbox-1"},
        {"providerName": "local-firecracker"},
        {"providerName": "", "sandboxId": "sandbox-1"},
        {"providerName": "local-firecracker", "sandboxId": "s", "opaque": "not a map"},
    ],
)
def test_a_malformed_stored_handle_is_a_defect_rather_than_an_answer(
    handle: Mapping[str, Any],
) -> None:
    """Not absorbed into `ConnectionNotIssuable`: that would hide a bug behind a lifecycle answer."""
    with pytest.raises(ItemShapeError):
        issuer().issue(session_record(sandbox_handle=handle))


# --- What comes back from the mint is checked -----------------------------------------------


def test_a_mint_that_widened_the_port_set_is_refused() -> None:
    """R11.4 is a claim about the credential, so it is checked on what came back."""
    mint = RecordingMint(override_ports=(SANDBOX_PROTOCOL_CONTROL_PORT, 9000))
    with pytest.raises(ConnectionNotIssuable, match="rather than to"):
        issuer(mint).issue(session_record())


def test_a_mint_that_ignored_the_ttl_is_refused() -> None:
    mint = RecordingMint(expiry_overshoot=timedelta(seconds=60))
    with pytest.raises(ConnectionNotIssuable, match="beyond the"):
        issuer(mint).issue(session_record(max_duration_seconds=120))


# --- The refresh route (R9.5) --------------------------------------------------------------


def event(session_id: str = SESSION_ID) -> dict[str, Any]:
    return {
        "version": "2.0",
        "rawPath": f"/sessions/{session_id}/connection",
        "requestContext": {
            "http": {"method": "POST"},
            "authorizer": {"iam": {"userArn": CALLER}},
        },
        "body": None,
        "isBase64Encoded": False,
    }


@dataclass
class Store:
    """An in-memory State_Store keyed exactly as DynamoDB is: partition key, then sort key."""

    items: dict[tuple[str, str], Mapping[str, Any]] = field(default_factory=dict)

    def put(self, record: SessionRecord) -> None:
        self.items[(record.pk, record.sort_key)] = record.to_item()

    def read_session(
        self, *, partition_key: str, sort_key: str
    ) -> Mapping[str, Any] | None:
        return self.items.get((partition_key, sort_key))


def dispatcher(
    record: SessionRecord, mint: RecordingMint | None = None
) -> ControlPlaneApi:
    store = Store()
    store.put(record)
    return ControlPlaneApi(
        operations=ConnectionOperations(issuer=issuer(mint)), lookup=store
    )


def test_the_refresh_route_returns_a_freshly_minted_descriptor() -> None:
    mint = RecordingMint()
    record = session_record(exposed_ports=(8080,))
    response = dispatcher(record, mint).handle(event())
    assert response.status == HTTPStatus.OK
    assert len(mint.calls) == 1
    body = response.body.decode()
    assert FAKE_TOKEN in body
    assert AUTH_HEADER in body


def test_the_refresh_response_is_the_designed_descriptor_shape() -> None:
    record = session_record(exposed_ports=(8080,), generation=2)
    payload = connection_payload(record, issuer().issue(record))
    assert set(payload) == {"sessionId", "generation", "lifecycleState", "connection"}
    # `resolution` belongs to ResolveSession alone, where R6.15 requires the distinction.
    assert "resolution" not in payload
    assert payload["generation"] == 2
    assert payload["connection"]["ports"] == [SANDBOX_PROTOCOL_CONTROL_PORT, 8080]


def test_refresh_adds_no_scoping_decision_of_its_own() -> None:
    """The route hands the record to the issuer, so refresh and creation derive one scope.

    A refresh that could produce a broader credential than the original would be R9.5 undoing
    R11.4, so the operation's body is asserted to pass the record and nothing else.
    """
    source = inspect.getsource(ConnectionOperations.refresh_connection)
    assert "self.issuer.issue(record)" in source
    for widening in ("ports", "ttl", "exposed_ports", "control_port"):
        assert widening not in source


def test_refresh_of_a_session_with_no_credential_available_is_a_409() -> None:
    record = session_record(lifecycle_state=LifecycleState.PENDING, with_handle=False)
    response = dispatcher(record).handle(event())
    assert response.status == HTTPStatus.CONFLICT
    assert b"PENDING" in response.body


def test_refresh_of_another_tenants_session_is_the_fixed_not_found() -> None:
    """Reached in the dispatcher, before the issuer, so a cross-tenant identifier cannot mint."""
    from control_plane.api import NOT_FOUND_RESPONSE

    mint = RecordingMint()
    store = Store()
    api = ControlPlaneApi(
        operations=ConnectionOperations(issuer=issuer(mint)), lookup=store
    )
    assert api.handle(event("01JNEVEREXISTEDBBBBBBBBBBB")) is NOT_FOUND_RESPONSE
    assert mint.calls == []


def test_the_other_seven_operations_still_answer_501() -> None:
    """This task fills one seam. The remaining seven keep naming the task that fills them."""
    record = session_record()
    store = Store()
    store.put(record)
    api = ControlPlaneApi(operations=ConnectionOperations(), lookup=store)
    response = api.handle(
        {
            "version": "2.0",
            "rawPath": f"/sessions/{SESSION_ID}",
            "requestContext": {
                "http": {"method": "GET"},
                "authorizer": {"iam": {"userArn": CALLER}},
            },
            "body": None,
        }
    )
    assert response.status == HTTPStatus.NOT_IMPLEMENTED


# --- The lint rule -------------------------------------------------------------------------


@pytest.mark.parametrize(
    "source",
    [
        "descriptor = provider.issue_connection(handle, ports, ttl)\n",
        (
            "from control_plane.providers.base import ComputeProvider\n"
            "d = ComputeProvider.issue_connection(p, h, (8000,), 900)\n"
        ),
        "def issue_connection(handle, ports, ttl_seconds):\n    return None\n",
        "async def issue_connection(handle, ports, ttl_seconds):\n    return None\n",
    ],
)
def test_the_rule_rejects_a_second_issuer(source: str) -> None:
    violations = rule.check_source(source, "control_plane/api/handlers.py")
    assert violations, f"no violation reported for: {source!r}"
    assert violations[0].describe().startswith("control_plane/api/handlers.py:")


@pytest.mark.parametrize(
    "source",
    [
        # Prose naming the mint is documentation, not an issuance.
        '"""Reaches issue_connection through the issuer."""\n',
        "# issue_connection is the mint.\nX = None\n",
        # Reading the name in order to assert the seam's shape is not calling it.
        "import inspect\ns = inspect.signature(ComputeProvider.issue_connection)\n",
        # The sanctioned path.
        "connection = self.issuer.issue(record)\n",
    ],
)
def test_the_rule_leaves_documentation_and_the_sanctioned_path_alone(
    source: str,
) -> None:
    assert rule.check_source(source, "control_plane/api/connection.py") == ()


def test_the_rule_reports_the_line_it_found() -> None:
    source = textwrap.dedent(
        """\
        def handler(record, provider):
            ports = (8000, 9000)
            return provider.issue_connection(record.handle, ports, 28_800)
        """
    )
    violations = rule.check_source(source, "control_plane/api/handlers.py")
    assert [violation.line for violation in violations] == [3]


def test_the_exemption_is_the_issuer_the_providers_and_the_exercising_tests() -> None:
    """The allow-list is enumerated and every entry exists, so an extra entry cannot hide in it."""
    assert rule.ALLOWED_MODULES == (
        {rule.ISSUER_MODULE} | rule.PROVIDER_MODULES | rule.ENFORCEMENT_MODULES
    )
    for relative in rule.ALLOWED_MODULES:
        assert (rule.REPOSITORY_ROOT / relative).is_file(), relative


def test_the_issuer_is_the_sole_caller_of_the_mint_in_the_repository() -> None:
    violations = rule.check_repository()
    assert not violations, (
        "modules other than the sole issuer call the credential mint: "
        + ", ".join(violation.describe() for violation in violations)
    )
