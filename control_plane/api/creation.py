# kiro-classification: public
"""`CreateSession` steps 2 and 3: write the record, then start the execution. Never provision.

The design fixes the creation sequence as validate, write the Session row, `StartExecution`, wait,
return. Step 1 is :mod:`control_plane.api.admission`. Steps 2 and 3 are here. Step 4, the wait, and
the `creationContract` switch that decides whether the handler waits at all, are
:mod:`control_plane.api.creation_wait` and reach this module through :class:`CreationWait` alone.

## The ordering, and what it buys

The previous ordering had the handler provision the Sandbox and then start the execution, which left
a window: a handler that died between the two calls left a running, billable Sandbox that no
orchestration governed. R6.10 and R6.11 close it by inverting the order, and this module is where
the inversion is expressed:

1. **The row is written first, and complete** (R6.6). Complete is the operative word. A partial row
   followed by provisioning would leave a Sandbox with no record of why it exists — unreapable,
   because the Reaper's only state source is the Session row, and unattributable, because the
   Tenant identifier lives on that row. So :meth:`CreationOperations.create_session` builds a whole
   :class:`~control_plane.state.records.SessionRecord` and writes it in one `Put`; there is no
   partial write anywhere on this path and no second write that adds a field R6.6 names.
2. **`StartExecution` follows, named after the Session** (R6.10). :func:`execution_name_for` is a
   pure function of the Session identifier, which is what makes a retry join the execution already
   running instead of starting a second one.
3. **Nothing here provisions** (R6.11). There is no `provider.provision` call in this module, and
   the only provider method reached from the creation path at all is `limits()`, inside admission,
   for the ceiling a rejection has to name. `ci/lint_rules/orchestrated_provisioning.py` fails the
   build if a `provision` call appears outside the Compute_Provider seam, so the claim is
   structural rather than conventional — the same posture as the Tenant partition key rule and the
   sole credential issuer rule.

The remaining orphan case is the design's case 1: the handler dies between the row write and
`StartExecution`, leaving a row in `PENDING` with no execution and no Sandbox. Nothing is billable
in that window, and the row is exactly what the Reaper's orphan pass keys on. That is why the row
is written *before* the execution rather than after: a row with no execution is recoverable, an
execution with no row is not.

## What is deliberately not here

**No provisioning, no credential minting and no wait.** The credential a `CreateSession` response
carries is read from the Session row where the orchestration published it (R6.13), so this module
neither calls a mint nor holds one — :class:`~control_plane.credentials.ConnectionIssuer` is the
sole issuer and the creation path does not reach it. A `CreationWait` that returns a descriptor is
reporting what it read from the store.

**No lifecycle state this module invents.** `PENDING` before the execution and `ORCHESTRATING`
after it are the two transitions the design's lifecycle table attributes to the Control_Plane
handler. Every later transition belongs to the orchestrator or the Reaper.

## The one seam the get-or-create path needs

The design's step 2 says that "on the get-or-create path this write is one half of a transaction".
That is the only difference between the two creation paths, so it is the only thing
:meth:`CreationOperations.create` parameterises: a :data:`SessionRowWriter` replaces the plain
conditional `Put` with the two-item `TransactWriteItems`
:mod:`control_plane.api.resolution` performs. Everything else — the validation, the completeness of
the row, the derived execution name, the ordering of the write against `StartExecution`, and the
wait — is shared code rather than a second implementation that has to be kept in agreement. There
is deliberately no second place where a Session row is built or an execution is started, because
R6.11's guarantee is about *every* Sandbox and a second creation path would be a second place to
get the ordering wrong.
"""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from http import HTTPStatus
from typing import TYPE_CHECKING, Any, Final, Protocol

from control_plane.api.admission import (
    AdmissionPolicy,
    AdmittedLimits,
    SessionAdmissionRejected,
    admit_session_creation,
)
from control_plane.api.handlers import (
    NotImplementedOperations,
    OperationRequest,
    OperationResult,
)
from control_plane.state.keys import tenant_state_sort_key
from control_plane.state.records import (
    ConnectionDescriptor,
    LifecycleState,
    SessionRecord,
)
from control_plane.tenancy import AuthenticatedPrincipal, pk_for

if TYPE_CHECKING:
    # Annotations only, so importing this module does not import the providers package and with it
    # every registration its `__init__` performs. The creation path reads two attributes of
    # whichever provider it is handed — `name`, and `limits()` from inside admission — and selects
    # none, so the runtime dependency would buy nothing.
    from control_plane.providers.base import ComputeProvider

__all__ = [
    "EXECUTION_NAME_PREFIX",
    "EXPOSED_PORTS_FIELD",
    "MAX_EXECUTION_NAME_LENGTH",
    "ORCHESTRATION_STARTED_REASON",
    "CreatedSession",
    "CreationOperations",
    "CreationSettings",
    "CreationWait",
    "ExecutionNameError",
    "NoCreationWait",
    "OrchestrationStart",
    "OrchestrationStarter",
    "SessionRowStore",
    "SessionRowWriter",
    "creation_payload",
    "execution_name_for",
    "new_session_id",
    "orchestration_start_for",
]

#: The `CreateSession` body field naming the ports an application inside the Sandbox will listen on.
#: Spelled as the record attribute it becomes, the same convention
#: :mod:`control_plane.api.admission` follows, so a request field and the stored attribute have one
#: vocabulary.
EXPOSED_PORTS_FIELD: Final = "exposedPorts"

#: Prefix of every Session_Orchestrator execution name. A prefix rather than the bare identifier so
#: that an execution listing is legible, and a constant rather than a literal at the call site so
#: the derivation has one spelling.
EXECUTION_NAME_PREFIX: Final = "session-"

#: Step Functions' bound on an execution name.
MAX_EXECUTION_NAME_LENGTH: Final = 80

#: The characters Step Functions rejects in an execution name. Whitespace and non-printable
#: characters are refused alongside them, in the check itself. A Session identifier is a 128-bit
#: random ULID in Crockford Base32, so none of these can occur in one; the check exists because an
#: identifier that reached here from somewhere else would otherwise fail at the API call with a
#: message about a name rather than about where the name came from.
_FORBIDDEN_IN_EXECUTION_NAME: Final = frozenset('<>{}[]?*"#%\\^|~`$&,;:/')

#: The `stateReason` the `PENDING` → `ORCHESTRATING` transition records (R14.2). A constant rather
#: than a literal at the call site, because the row and the record this handler returns must give an
#: operator the same answer and a second spelling is how they would stop doing so.
ORCHESTRATION_STARTED_REASON: Final = "orchestration started"

#: Crockford Base32, the ULID alphabet. Excludes I, L, O and U, so an identifier read aloud or
#: copied out of a log cannot be transcribed into a different one.
_CROCKFORD_BASE32: Final = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

#: 26 Crockford Base32 characters carry the 128 bits of a ULID.
_SESSION_ID_LENGTH: Final = 26

_BITS_PER_CHARACTER: Final = 5
_SESSION_ID_BITS: Final = 128
_MILLISECONDS_PER_SECOND: Final = 1000
_MAX_PORT: Final = 65535


class ExecutionNameError(ValueError):
    """A Session identifier cannot become a Step Functions execution name.

    A defect rather than a caller's mistake: the identifiers this module generates always can, so
    this is raised only for one that arrived from somewhere else.
    """


def new_session_id() -> str:
    """Return a fresh Session identifier: a 128-bit random ULID in Crockford Base32.

    Fully random rather than time-prefixed. The design's Layer 3 rests on a Session's existence
    being unprobeable, and a timestamp prefix would narrow the search space around a known Session
    to whatever was created in the same millisecond. :func:`secrets.randbits` rather than
    :mod:`random`, for the same reason.
    """
    value = secrets.randbits(_SESSION_ID_BITS)
    characters = []
    for _ in range(_SESSION_ID_LENGTH):
        characters.append(_CROCKFORD_BASE32[value & 0b11111])
        value >>= _BITS_PER_CHARACTER
    return "".join(reversed(characters))


def execution_name_for(session_id: str) -> str:
    """Return the Session_Orchestrator execution name for this Session (R6.10).

    **This is a pure function of the Session identifier and of nothing else.** No timestamp, no
    attempt counter, no random component. That is the whole of the idempotency R6.10 asks for:
    Step Functions treats `StartExecution` with a name that already exists as a request for the
    execution that has it, so a `CreateSession` retried for the same Session recomputes the same
    name and joins the execution already running rather than starting a second one. A name carrying
    anything else would produce a second execution, and with it a second Sandbox provisioned for
    one Session.

    It is also the correlation identifier R14.3 names: the Session identifier appears in the audit
    record, in this execution name and in the Sandbox log stream name, so one value walks an
    operator through all three.

    Raises:
        ExecutionNameError: the identifier is empty, or long enough or odd enough that the derived
            name is not one Step Functions accepts.
    """
    if not session_id:
        raise ExecutionNameError("a Session identifier must not be empty")
    offending = sorted(
        {
            character
            for character in session_id
            if character in _FORBIDDEN_IN_EXECUTION_NAME
            or character.isspace()
            or not character.isprintable()
        }
    )
    if offending:
        raise ExecutionNameError(
            f"a Session identifier must not contain {offending!r}: {session_id!r}"
        )
    name = f"{EXECUTION_NAME_PREFIX}{session_id}"
    if len(name) > MAX_EXECUTION_NAME_LENGTH:
        raise ExecutionNameError(
            f"the execution name derived from {session_id!r} is {len(name)} characters, "
            f"over the Step Functions limit of {MAX_EXECUTION_NAME_LENGTH}"
        )
    return name


@dataclass(frozen=True, slots=True)
class CreationSettings:
    """The deployment-configured row fields no caller supplies.

    Every field is required, with no literal default. These are the design's declared
    configuration — CDK context values — and a default here would be a second source for a number
    the deployment owns, which is the same reason :class:`~control_plane.api.admission
    .AdmissionPolicy` has none.

    `reap_shard_count` is the number of shards the Reaper sweeps. It belongs here rather than in
    the Reaper because the shard is written onto the row at creation and the Reaper reads it; one
    side has to own the modulus and the writer is the side that cannot get it wrong later.
    """

    memory_bytes: int
    execution_role_arn: str
    artifact_retention_days: int
    reap_shard_count: int
    continuation_enabled: bool = False
    continuation_paths: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.memory_bytes <= 0:
            raise ValueError(f"memory_bytes must be positive: {self.memory_bytes}")
        if not self.execution_role_arn:
            raise ValueError("execution_role_arn must not be empty")
        if self.artifact_retention_days < 0:
            raise ValueError(
                f"artifact_retention_days must not be negative: "
                f"{self.artifact_retention_days}"
            )
        if self.reap_shard_count <= 0:
            raise ValueError(
                f"reap_shard_count must be positive: {self.reap_shard_count}"
            )
        if self.continuation_paths and not self.continuation_enabled:
            raise ValueError(
                "continuation_paths are declared while continuation is disabled, so nothing "
                "would restore them"
            )


@dataclass(frozen=True, slots=True)
class OrchestrationStart:
    """The `PENDING` → `ORCHESTRATING` write, with its index key derived rather than supplied.

    One value object rather than four loose keyword arguments, for the reason
    :class:`~control_plane.lifecycle.LiveTransition` is one: every attribute of a lifecycle write
    that has to move together is carried by a single type, so no call site chooses part of it and no
    call site can omit part of it.

    It goes one step further than that module, and the step is the point. `stateCreatedAt` is the
    `tenant-state-index` sort key and it is `<lifecycleState>#<createdAt>`, so a row whose state
    moved without it would be returned by `ListSessions` under the state it used to hold and missed
    under the one it holds now. Here that attribute is **not a field**: it is
    :attr:`state_created_at`, a property computed from :attr:`state` and :attr:`created_at` through
    the same :func:`~control_plane.state.keys.tenant_state_sort_key` every other key derivation
    uses. There is therefore no value of this type in which the two disagree — not because a builder
    is careful, but because the disagreement has nowhere to live.

    :attr:`created_at` is carried for that derivation alone. It is never written; the row has held it
    since its first write and this is an update, so it appears here only because DynamoDB cannot
    compose a string in an update expression and the sort key must arrive already composed. That is
    the same reason `createdAt` is projected into `deadline-index` for the Reaper's own lifecycle
    write.

    Raises:
        ValueError: `state` is terminal, `execution_arn` is empty, or `state_reason` is blank. A
            terminal state is refused because this is an `UpdateItem` and nothing more: recording one
            must also delete the Affinity_Key binding (R10.16), which is
            :meth:`~control_plane.lifecycle.SessionLifecycleStore.settle_terminal_state` and never
            this.
    """

    partition_key: str
    sort_key: str
    execution_arn: str
    updated_at: int
    created_at: int
    state: LifecycleState
    state_reason: str

    def __post_init__(self) -> None:
        if self.state.is_terminal:  # nosemgrep: is-function-without-parentheses — @property
            raise ValueError(
                f"{self.state.value} is terminal, so recording it must also delete the "
                f"Affinity_Key binding (R10.16); the creation path writes live states only"
            )
        if not self.execution_arn:
            raise ValueError(
                "an orchestration start must name the execution it started"
            )
        if not self.state_reason.strip():
            raise ValueError(f"a transition to {self.state.value} must record a reason")

    @property
    def state_created_at(self) -> str:
        """The `tenant-state-index` sort key this write moves the row to.

        Derived, so it cannot be passed in wrongly and cannot be left behind.
        """
        return tenant_state_sort_key(self.state.value, self.created_at)


def orchestration_start_for(
    record: SessionRecord, *, execution_arn: str, at: int
) -> OrchestrationStart:
    """Build the `ORCHESTRATING` write for this Session row and the execution now governing it.

    Every field comes off the record, so a write cannot name a row in one partition and carry a key
    derived from another — the shape :func:`~control_plane.lifecycle.live_transition_for` established
    and the only way an :class:`OrchestrationStart` is built in the Control_Plane.
    """
    return OrchestrationStart(
        partition_key=record.pk,
        sort_key=record.sort_key,
        execution_arn=execution_arn,
        updated_at=at,
        created_at=record.created_at,
        state=LifecycleState.ORCHESTRATING,
        state_reason=ORCHESTRATION_STARTED_REASON,
    )


class SessionRowStore(Protocol):
    """The two writes the creation path performs, in the order it performs them.

    Both touch one item in the caller's own Tenant partition and both are reached with the same
    per-request tenant-confined credentials, so they are one seam rather than two. A structural
    type, so the offline suite drives the whole path against an in-memory store keyed as DynamoDB
    is, with no deployed resource and no network.
    """

    def put_new_session(self, item: Mapping[str, Any]) -> None:
        """Create the Session row, refusing to overwrite an item already at that key.

        Conditional on absence rather than an unconditional `Put`: the identifier is 128 bits of
        randomness so a collision is not a case to plan for, but overwriting a live Session's row
        would orphan its Sandbox, and "cannot happen" is a weaker guarantee than "the write would
        fail".
        """
        ...

    def mark_orchestration_started(self, start: OrchestrationStart) -> None:
        """Move the row to `start.state` and record the execution now governing it.

        `SET lifecycleState = :state, stateReason = :reason, orchestrationExecutionArn = :arn,
        updatedAt = :at, stateCreatedAt = :stateCreatedAt` under
        `ConditionExpression: attribute_exists(pk)`.

        A separate update rather than part of the first write, because the execution ARN does not
        exist until `StartExecution` has returned. The design's Session record table says as much:
        `orchestrationExecutionArn` is absent only in the orphan window between the row write and
        `StartExecution`.

        It takes one :class:`OrchestrationStart` and nothing else, which is what makes
        `stateCreatedAt` reachable at all: the contract this replaced had no parameter through which
        an implementation could refresh the `tenant-state-index` sort key, so no implementation could,
        and every row this write touched stayed indexed under `PENDING`. An implementation that now
        writes `lifecycleState` reads both values off one object, and the second is a function of the
        first.
        """
        ...


class OrchestrationStarter(Protocol):
    """`StartExecution` on the Session_Orchestrator, and nothing else.

    One method, in the shape :class:`~runtime.ports.PortRouting` established: the handler knows
    the execution name and the input, the deployment knows the state machine ARN, and nothing else
    passes between them. Returning the execution ARN is what lets the row record its governor.

    The implementation is expected to be idempotent for a repeated name — which is what Step
    Functions itself does — and :func:`execution_name_for` is what makes that reachable.
    """

    def start_execution(self, *, name: str, payload: Mapping[str, Any]) -> str:
        """Start, or join, the execution with this name, returning its ARN."""
        ...


class CreationWait(Protocol):
    """Step 4 of creation, implemented in :mod:`control_plane.api.creation_wait`.

    Declared here because step 3 has to hand the wait something and the shape of that handoff is a
    property of this module's output: the wait is a function of a written Session row rather than
    of a request, which is what lets the get-or-create loser reuse it verbatim (R6.19).

    A wait returns the credential it read from the Session row, or `None` when none was published
    inside its budget. It never mints one and never calls a provider, because R6.13 requires the
    returned credential to come from the State_Store.
    """

    def await_connection(self, record: SessionRecord) -> ConnectionDescriptor | None:
        """Return the published connection credential, or `None` if none appeared."""
        ...


@dataclass(frozen=True, slots=True)
class NoCreationWait:
    """The wait a deployment that has configured none has: it waits for nothing.

    This is the asynchronous creation contract's behaviour, and it is the honest default for a
    deployment with no configured wait budget — `202` with a Session identifier the caller can
    poll, rather than a blocked handler with no budget to bound it.
    :class:`~control_plane.api.creation_wait.PollingCreationWait` is the synchronous contract's
    wait and :func:`~control_plane.api.creation_wait.wait_for_contract` is the switch that selects
    between the two.
    """

    def await_connection(self, record: SessionRecord) -> ConnectionDescriptor | None:
        del record
        return None


#: How a created Session row reaches the store. The default is
#: :meth:`SessionRowStore.put_new_session`; the get-or-create path substitutes the two-item
#: transaction that writes the row and claims the Affinity_Key binding together (R6.18).
#:
#: It takes the finished item rather than the record, so a writer cannot alter what R6.6 requires
#: to be written — it decides only how, and under which condition, the item is committed.
SessionRowWriter = Callable[[Mapping[str, Any]], None]


@dataclass(frozen=True, slots=True)
class CreatedSession:
    """The outcome of steps 1 to 4: the row as it now stands, and any published credential.

    Returned by :meth:`CreationOperations.create` so that a caller which is not `POST /sessions` —
    the get-or-create create branch is the only one — renders its own response shape over the same
    creation. `connection` is `None` when nothing was published inside the wait's budget, which is
    the asynchronous contract's shape rather than a failure (R10.14).
    """

    record: SessionRecord
    connection: ConnectionDescriptor | None


def creation_payload(
    record: SessionRecord, connection: ConnectionDescriptor | None
) -> dict[str, Any]:
    """The `CreateSession` response body of the design's two creation contracts.

    `connection` is omitted rather than sent as null when none was published, because the SDK and
    the Agent_Tool_Interface treat an absent `connection` as "not yet published" and poll
    `GetSession`; a null would be a third state both would have to learn.
    """
    payload: dict[str, Any] = {
        "sessionId": record.session_id,
        "lifecycleState": record.lifecycle_state.value,
    }
    if connection is not None:
        payload["connection"] = connection.to_map()
    return payload


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _epoch_milliseconds(moment: datetime) -> int:
    """Epoch milliseconds for an aware instant, the unit every record timestamp uses."""
    if moment.tzinfo is None:
        raise ValueError("the creation clock must return an aware datetime")
    return int(moment.timestamp() * _MILLISECONDS_PER_SECOND)


def _requested_ports(body: Mapping[str, Any]) -> tuple[int, ...]:
    """Read the declared exposed port set, deduplicated and sorted.

    Rejected with :class:`~control_plane.api.admission.SessionAdmissionRejected` rather than
    allowed to reach :class:`~control_plane.state.records.SessionRecord`, whose own range check
    would surface a caller's mistake as a `500`. It is read here rather than in admission because
    it is not one of the three duration rules that module owns and carries no acceptance criterion
    of its own; it shares admission's error code so a caller sees one code for a configuration
    they got wrong.

    Sorted and deduplicated at the boundary, so the stored set and the credential scoped to it
    (R11.4) are comparable without either side normalising again.
    """
    value = body.get(EXPOSED_PORTS_FIELD)
    if value is None:
        return ()
    if isinstance(value, (str, bytes)) or not isinstance(value, (list, tuple)):
        raise SessionAdmissionRejected(
            f"{EXPOSED_PORTS_FIELD} must be a list of port numbers"
        )
    ports: set[int] = set()
    for element in value:
        if isinstance(element, bool) or not isinstance(element, int):
            raise SessionAdmissionRejected(
                f"{EXPOSED_PORTS_FIELD} must contain only port numbers"
            )
        if not 1 <= element <= _MAX_PORT:
            raise SessionAdmissionRejected(
                f"{EXPOSED_PORTS_FIELD} contains {element}, which is not a port between 1 "
                f"and {_MAX_PORT}"
            )
        ports.add(element)
    return tuple(sorted(ports))


@dataclass(frozen=True, slots=True)
class CreationOperations(NotImplementedOperations):
    """The operation this task implements: `CreateSession`, and no other.

    Inherits the remaining seven seams so the routes those tasks own keep answering `501` naming
    the task that fills them, which is the shape
    :class:`~control_plane.api.connection.ConnectionOperations` established.

    Every collaborator is injected. The provider is held for its name and for the ceiling admission
    reads from it, never to provision: see this module's docstring and the lint rule it names.
    """

    provider: ComputeProvider
    policy: AdmissionPolicy
    settings: CreationSettings
    store: SessionRowStore
    orchestration: OrchestrationStarter
    wait: CreationWait = field(default_factory=NoCreationWait)
    clock: Callable[[], datetime] = _utc_now
    session_ids: Callable[[], str] = new_session_id

    def create_session(self, request: OperationRequest) -> OperationResult:
        """`POST /sessions`: create a Session and render the creation response.

        The creation itself is :meth:`create`; this method is the rendering, which is why the
        get-or-create create branch can share the former without inheriting a `201`/`202` shape
        that says nothing about which of R6.15's two actions happened.
        """
        created = self.create(request.principal, request.body)
        status = (
            HTTPStatus.CREATED
            if created.connection is not None
            else HTTPStatus.ACCEPTED
        )
        return OperationResult(
            payload=creation_payload(created.record, created.connection), status=status
        )

    def create(
        self,
        principal: AuthenticatedPrincipal,
        body: Mapping[str, Any],
        *,
        write: SessionRowWriter | None = None,
        affinity_key_digest: str | None = None,
    ) -> CreatedSession:
        """Validate, write the complete row, start the execution, wait, and report.

        The order of the four steps below is the requirement, and this is the only place in the
        Control_Plane where they appear. Nothing between the row write and `StartExecution` can
        provision, because no code on this path can provision at all.

        Args:
            principal: the authenticated caller. The sole source of the Tenant identifier and,
                through :func:`~control_plane.tenancy.pk_for`, of the partition key.
            body: the request body the limits are admitted from.
            write: how the finished row reaches the store. `None` is the plain conditional `Put`;
                the get-or-create path passes the two-item transaction that also claims the
                Affinity_Key binding. A writer that refuses raises before any execution exists, so
                a refused claim costs no execution and no Sandbox.
            affinity_key_digest: recorded on the row when this Session was created through
                get-or-create, so the Reaper can delete the binding without scanning (R10.17).

        Raises:
            SessionAdmissionRejected: the body fails one of admission's three rules.
        """
        limits = admit_session_creation(
            body, provider=self.provider, policy=self.policy
        )
        record = self._pending_record(
            principal, body, limits, affinity_key_digest=affinity_key_digest
        )

        # Step 2 (R6.6). Complete, and before any execution exists.
        (self.store.put_new_session if write is None else write)(record.to_item())

        # Step 3 (R6.10, R6.11). Every Sandbox that can exist for this Session is provisioned
        # inside this execution, so it cannot precede it.
        execution_arn = self.orchestration.start_execution(
            name=execution_name_for(record.session_id),
            payload=self._execution_input(record),
        )
        orchestrating = self._mark_orchestrating(record, execution_arn)

        # Step 4. The default wait waits for nothing, which is the asynchronous contract.
        return CreatedSession(
            record=orchestrating, connection=self.wait.await_connection(orchestrating)
        )

    # -- the record, and the two writes -----------------------------------------------------

    def _pending_record(
        self,
        principal: AuthenticatedPrincipal,
        body: Mapping[str, Any],
        limits: AdmittedLimits,
        *,
        affinity_key_digest: str | None = None,
    ) -> SessionRecord:
        """Build the complete Session row, in `PENDING`, before anything is written.

        Every field R6.6 names is populated here: the Tenant identifier, the Compute_Provider name,
        the lifecycle state, the creation timestamp and all four configured limits. The limits are
        assigned straight off :class:`~control_plane.api.admission.AdmittedLimits`, whose field
        names are this record's, so there is no mapping step between validation and storage for a
        value to be lost in.

        The partition key comes from :func:`~control_plane.tenancy.pk_for` and the Tenant
        identifier from the principal, so neither can arrive from the body.

        `affinity_key_digest` is part of the row from the first write rather than added by a later
        update, which is what makes cleanup layer 2 total: a row that reached the store at all
        carries the digest the Reaper needs to delete its binding (R10.17).
        """
        created_at = _epoch_milliseconds(self.clock())
        session_id = self.session_ids()
        return SessionRecord(
            pk=pk_for(principal),
            session_id=session_id,
            tenant_id=principal.tenant_id,
            provider_name=self.provider.name,
            lifecycle_state=LifecycleState.PENDING,
            created_at=created_at,
            updated_at=created_at,
            max_duration_seconds=limits.max_duration_seconds,
            idle_seconds=limits.idle_seconds,
            suspended_seconds=limits.suspended_seconds,
            auto_resume=limits.auto_resume,
            memory_bytes=self.settings.memory_bytes,
            execution_role_arn=self.settings.execution_role_arn,
            reap_shard=self._reap_shard(session_id),
            reap_deadline=created_at
            + limits.max_duration_seconds * _MILLISECONDS_PER_SECOND,
            artifact_retention_days=self.settings.artifact_retention_days,
            exposed_ports=_requested_ports(body),
            continuation_enabled=self.settings.continuation_enabled,
            continuation_paths=self.settings.continuation_paths,
            persistence=bool(body.get("persistence", False)),
            workspace_affinity_key=str(body.get("affinityKey", "")) if body.get("persistence") else "",
            principal_id=principal.caller_identity,
            state_reason="created",
            affinity_key_digest=affinity_key_digest,
        )

    def _mark_orchestrating(
        self, record: SessionRecord, execution_arn: str
    ) -> SessionRecord:
        """Record the started execution and return the row as it now stands.

        Returning the updated record rather than re-reading it is deliberate: the wait and the
        response both describe the row this handler just wrote, and a re-read would be a second
        strongly consistent `GetItem` that could only ever return what is already in hand.
        """
        start = orchestration_start_for(
            record,
            execution_arn=execution_arn,
            at=_epoch_milliseconds(self.clock()),
        )
        self.store.mark_orchestration_started(start)
        # The same object the store was handed, so the row and the record this handler returns cannot
        # describe two different transitions. `state_created_at` needs no mention: it is a function
        # of the state and of `createdAt`, on the record as it is on the write.
        return replace(
            record,
            lifecycle_state=start.state,
            updated_at=start.updated_at,
            orchestration_execution_arn=start.execution_arn,
            state_reason=start.state_reason,
        )

    def _reap_shard(self, session_id: str) -> int:
        """Assign the `deadline-index` shard this row is swept in.

        Derived from the Session identifier rather than drawn at random, so a row's shard is
        recoverable from the row's own key if the attribute is ever in doubt. A digest rather than
        :func:`hash`, which is salted per process and would place one Session in different shards in
        two invocations, and rather than a sum of the identifier's bytes, which would not spread
        evenly across an arbitrary shard count.
        """
        digest = hashlib.sha256(session_id.encode("utf-8")).digest()
        return int.from_bytes(digest, "big") % self.settings.reap_shard_count

    def _execution_input(self, record: SessionRecord) -> dict[str, Any]:
        """The execution input: what the orchestrator needs to provision and govern.

        The Session identifier, the Tenant, the provider to call, the limits and the port set —
        the design's flowchart input, plus the provider name, without which the orchestrator would
        have to guess which registered provider this Session was admitted against.

        No credential and no partition key: the orchestrator derives its own key from the Tenant
        identifier through the same sole producer, and it mints the connection credential itself
        after `/run` has returned 200 (R6.12).
        """
        result: dict[str, Any] = {
            "sessionId": record.session_id,
            "tenantId": record.tenant_id,
            "principalId": record.principal_id,
            "providerName": record.provider_name,
            "limits": {
                "maxDurationSeconds": record.max_duration_seconds,
                "idleSeconds": record.idle_seconds,
                "suspendedSeconds": record.suspended_seconds,
                "autoResume": record.auto_resume,
                "memoryBytes": record.memory_bytes,
            },
            "exposedPorts": list(record.exposed_ports),
            "executionRoleArn": record.execution_role_arn,
            "generation": record.generation,
        }
        # Pass persistence flag and affinity key to the orchestrator
        if record.persistence:
            result["persistence"] = True
        if record.workspace_affinity_key:
            result["affinityKey"] = record.workspace_affinity_key
        return result
