# kiro-classification: public
"""The duration-ceiling handoff: what survives it, what does not, and the writes that say so.

R10.11: a Session needing longer than the 28,800 s ceiling has its filesystem state persisted to the
State_Store and a replacement Sandbox provisioned that restores it. The design's *Duration ceiling
continuation* section draws the sequence; this module holds the types, the derivations and the two
seams that sequence needs, and :meth:`~control_plane.orchestrator.tasks.SessionOrchestrator.continue_session`
holds the ordering. The split is the same one the rest of the package makes: the module that touches
a Compute_Provider is `tasks.py` and no other, so the step ordering lives there and the shapes live
here.

## What survives, and what is replaced

The Session identifier survives. So does the Affinity_Key binding, and therefore the caller's
ability to reconnect. **The Sandbox does not**: its handle, its endpoint, its Family A credential and
its `generation` are all replaced, and every process, every open connection and all memory state is
gone. Continuation is not suspend and resume — R13.2 preserves memory and disk and is transparent to
a caller, and this preserves a *declared path set* on disk and nothing else. The design enumerates
the losses; the one that matters most is memory, entirely, which is why continuation is opt-in per
Session through `continuationEnabled` rather than automatic.

## R6.24 needs no code here, and that is the point

The Affinity_Key binding names the **Session identifier and nothing else** — no Sandbox handle, no
generation, no credential, no lifecycle state (see
:class:`~control_plane.state.records.AffinityKeyBindingRecord`). A continuation replaces the Sandbox
and increments `generation` while the Session identifier stays fixed, so the binding is already
correct after the handoff and **no write in this module touches it**. There is deliberately no
binding parameter on :class:`ContinuationHandoff` and no binding method on
:class:`ContinuationStore`, so R6.24 holds by there being no code path that could break it rather
than by one that maintains it. :mod:`control_plane.api.resolution` states the same fact from the
read side.

The corollary matters for the ordering in `tasks.py`: the provider's terminal report for the outgoing
Sandbox is **not** mirrored through :class:`~control_plane.lifecycle.LifecycleReconciler` during a
handoff. Mirroring it would settle the Session and delete its binding with it (R10.16), which is the
one thing R6.24 forbids on this path. The row stays `CONTINUING` instead, and `CONTINUING` being one
of the three record-only lifecycle states — no provider can report it — is exactly what makes that
sound: it is a state this component decides on, not a report it echoes.

## Why the artifact reference is derived rather than chosen

The archive of generation *N* lives at
`tenants/<tenantId>/sessions/<sessionId>/<N>/{artifact}`, produced by
:func:`~control_plane.state.artifacts.artifact_object_key`. The generation segment already exists in
that layout for this reason: a handoff must not overwrite the artifacts of the generation it
replaced. So the reference is a function of the row, computed by
:func:`continuation_artifact_reference`, and there is no field anywhere for a caller or a deployment
to choose a different one.

That derivation is also what makes the *outgoing* half work at all. The `/terminate` hook archives to
a reference it was handed at `/run` (R7.9, R13.3), so generation *N*'s archive destination is settled
when generation *N* is provisioned, not when the ceiling arrives. :meth:`ContinuationHandoffs.start_configuration`
is where both halves of one document are composed: a `persist` request naming this generation's
reference and the declared path set, and — for a generation that was reached *by* a handoff — a
`restore` request naming the reference recorded for it.

## The continuation record is load-bearing, not decorative

:class:`~control_plane.state.records.ContinuationRecord` is keyed
`S#<sessionId>#C#<generation>`, and this module writes it under the **incoming** generation: the
record at `C#<N+1>` names the artifact generation *N* wrote, because the reader of that record is the
Sandbox that restores from it. A generation with no such record has nothing to restore, which is the
honest description of generation 1.

Deriving `key(generation - 1)` at provision time instead would have made the record decorative and
would have let a restore name an archive that was never written. Reading the record means a restore
is attempted only where a handoff recorded one, and a `/run` hook that cannot fetch it reports the
restoration failure R13.7 requires rather than starting empty and pretending.

## Idempotence is a condition, not a check

Step Functions retries a task Lambda. A replayed handoff must not increment `generation` twice, and
it must not leave the row naming an archive that was never written. Both are conditions on the
writes rather than reads the caller performs first:

- :meth:`ContinuationStore.record_continuation` is conditional on the item's absence, so the first
  record for a generation stands, in the same posture as
  :meth:`~control_plane.api.creation.SessionRowStore.put_new_session` and the claim ledger.
- :meth:`ContinuationStore.apply_continuation` is conditional on `generation = :outgoing`. A replay
  finds the row already at `N+1` and the write is refused, which is absorption working rather than an
  error — the same shape as :data:`~control_plane.lifecycle.ABSORBING_LIFECYCLE_STATES`.

A replay that arrives *after* the generation increment has one more problem, and
:meth:`ContinuationHandoffs.applied_handoff` is it: the increment drops the outgoing handle, so such a
replay has no Sandbox to name and would be refused as a row out of order — failing a Session whose
handoff in fact completed. Recognising it costs one read, which is sound here because the only
concurrency on this path is a *sequential* retry of one task by one execution.

No second Sandbox can result from a replay either way, because **nothing here provisions**. The
graph's `Continue → Provision` edge is what provisions, `Provision` carries no retrier, and it is
reached once per traversal of the governing choice.

## The document keys are spelled again, deliberately

`runtime/run_config.py` parses this document, and `control_plane/` imports nothing from `runtime/`:
the runtime runs inside the untrusted MicroVM and this code runs under the Control_Plane's execution
role. So the four key names below are a second spelling of the runtime's private constants, in the
same posture as :data:`~control_plane.credentials.SANDBOX_PROTOCOL_CONTROL_PORT` against
`runtime.server.DEFAULT_PORT` and `MAX_RUN_CONFIG_BYTES` against
:attr:`~control_plane.providers.base.ProviderLimits.max_run_config_bytes`. One test in the offline
suite imports both sides and asserts the document this module composes parses to the values it
intended, which is the only thing that keeps the two spellings in step.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final, Protocol

from control_plane.state.artifacts import artifact_object_key
from control_plane.state.keys import continuation_sort_key
from control_plane.state.records import (
    ContinuationRecord,
    LifecycleState,
    SessionRecord,
)

__all__ = [
    "CONTINUATION_ARTIFACT_ID",
    "CONTINUATION_REASON",
    "PATHS_KEY",
    "PERSIST_KEY",
    "REFERENCE_KEY",
    "RESTORE_KEY",
    "ContinuationAlreadyRecorded",
    "ContinuationHandoff",
    "ContinuationHandoffs",
    "ContinuationNotEnabled",
    "ContinuationStore",
    "SandboxQuiesce",
    "StartConfiguration",
    "continuation_artifact_reference",
    "continuation_record_for",
    "handoff_for",
]

#: The artifact identifier of one generation's continuation archive, within that generation's own
#: artifact prefix. One name rather than a generated one, because the generation segment already
#: makes the key unique and a derived name is recoverable from the row alone: an operator holding a
#: Session identifier and a generation can name the object without reading anything.
#:
#: It carries a `/` because an artifact identifier is a relative path within the Session's artifact
#: tree, which :func:`~control_plane.state.artifacts.artifact_object_key` validates segment by
#: segment. It carries no `#`, which the same validation and
#: :func:`~control_plane.state.keys.artifact_sort_key` both refuse.
CONTINUATION_ARTIFACT_ID: Final = "continuation/state.tar"

#: The `stateReason` recorded on the `CONTINUING` transition.
#:
#: It names no generation on purpose. A replayed handoff re-writes this transition before its own
#: conditional write is refused, so a reason carrying the outgoing number would be stale exactly when
#: it was re-written. The numbers live on `generation` and on the continuation record, which are the
#: two places that cannot go stale; this string is the prose R14.2 asks an operator to be able to
#: read.
CONTINUATION_REASON: Final = (
    "the configured maximum duration is within the continuation lead, so the declared path set is "
    "being persisted and a replacement Sandbox provisioned to restore it (R10.11)"
)

#: The four run-configuration document keys this module composes. Second spellings of
#: `runtime.run_config`'s private constants, across a boundary neither side may import across; see
#: the module docstring.
RESTORE_KEY: Final = "restore"
PERSIST_KEY: Final = "persist"
REFERENCE_KEY: Final = "reference"
PATHS_KEY: Final = "paths"


class ContinuationNotEnabled(Exception):
    """A handoff was attempted for a Session that did not declare one.

    A defect rather than an operational condition. Continuation is declared configuration recorded on
    the Session row, and the governing loop's decision already requires `continuationEnabled` before
    it can answer `continue`, so reaching here means the row and the decision disagree. Refusing is
    what stops a Sandbox being torn down for a Session that never asked to be handed off and whose
    outgoing generation therefore carries no `persist` request to have archived anything.
    """

    def __init__(self, session_id: str) -> None:
        super().__init__(
            f"Session {session_id!r} did not declare continuation, so there is no declared path "
            f"set to persist and no handoff to perform (R10.11)"
        )
        self.session_id = session_id


class ContinuationAlreadyRecorded(Exception):
    """A continuation record already exists for the incoming generation.

    DynamoDB's `ConditionalCheckFailedException` on a conditional `PutItem`, at this seam. It is a
    replayed handoff rather than a failure — the first record for a generation stands, in the same
    posture the first terminal lifecycle state and the first quarantine reason do — so the caller
    absorbs it and reports it rather than raising.
    """

    def __init__(self, session_id: str, generation: int) -> None:
        super().__init__(
            f"Session {session_id!r} already carries a continuation record for generation "
            f"{generation}"
        )
        self.session_id = session_id
        self.generation = generation


@dataclass(frozen=True, slots=True)
class StartConfiguration:
    """The per-Session configuration document a Sandbox starts with, or the reference to it.

    Two fields because R7.11 gives the payload two shapes: inline while it fits the provider's
    declared `max_run_config_bytes`, and a State_Store reference when it does not. Which of the two a
    provider carries is the provider's decision, not this module's.

    The default carries neither, which is a Sandbox that starts with nothing declared and nothing to
    restore. That is what a Session with continuation disabled gets, and the only such Session:
    :meth:`ContinuationHandoffs.start_configuration` composes a document for every generation of a
    continuing Session, including the first, because the first is the one whose `/terminate` hook has
    to write the archive the second restores from.
    """

    document: bytes = b""
    reference: str | None = None


@dataclass(frozen=True, slots=True)
class ContinuationHandoff:
    """The write that replaces the Sandbox of a Session without replacing the Session.

    **It carries no lifecycle state and no binding key**, which is the whole of its shape. The
    `CONTINUING` transition is a :class:`~control_plane.lifecycle.LiveTransition` committed through
    :mod:`control_plane.lifecycle` like every other lifecycle write in this package, and the binding
    is untouched (R6.24) — so this type has no field through which either could travel, in the same
    posture as :class:`~control_plane.orchestrator.tasks.SandboxRecording` and
    :class:`~control_plane.orchestrator.tasks.CredentialPublication`.

    :attr:`incoming_generation` is a **derived property with no backing field**, the shape
    :attr:`~control_plane.api.creation.OrchestrationStart.state_created_at` established: the value
    written and the value the condition tests are one number and one increment, so no value of this
    type exists in which they disagree.

    Raises:
        ValueError: `outgoing_generation` is not a generation that ever existed. A Session's
            generation starts at 1, so 0 and below name nothing.
    """

    partition_key: str
    sort_key: str
    outgoing_generation: int
    updated_at: int

    def __post_init__(self) -> None:
        if self.outgoing_generation < 1:
            raise ValueError(
                f"a generation starts at 1, so {self.outgoing_generation} is not one a handoff "
                f"could leave"
            )

    @property
    def incoming_generation(self) -> int:
        """The generation the replacement Sandbox is recorded under."""
        return self.outgoing_generation + 1


def handoff_for(record: SessionRecord, *, at: int) -> ContinuationHandoff:
    """Build the handoff that moves this Session off its current generation.

    Every field comes off the record, so a handoff cannot name a row in one partition and a
    generation read from another — the shape
    :func:`~control_plane.lifecycle.live_transition_for` established and the only way a
    :class:`ContinuationHandoff` is built.
    """
    return ContinuationHandoff(
        partition_key=record.pk,
        sort_key=record.sort_key,
        outgoing_generation=record.generation,
        updated_at=at,
    )


def continuation_artifact_reference(record: SessionRecord, generation: int) -> str:
    """The State_Store reference of one generation's continuation archive.

    Derived from the Tenant, the Session and the generation through the sole producer of an artifact
    object key, so the object a `persist` request writes and the object a `restore` request fetches
    are the same key by construction rather than by two spellings that happen to agree.

    Raises:
        ArtifactLayoutError: an identifier cannot safely become part of a key, or the generation is
            below 1.
    """
    return artifact_object_key(
        record.tenant_id, record.session_id, generation, CONTINUATION_ARTIFACT_ID
    )


def continuation_record_for(
    record: SessionRecord, handoff: ContinuationHandoff, *, at: int
) -> ContinuationRecord:
    """Build the continuation record this handoff writes.

    Keyed under the **incoming** generation and naming the **outgoing** generation's archive, because
    the reader of this record is the Sandbox that restores from it. Both numbers come off one
    :class:`ContinuationHandoff`, whose increment is derived, so the key and the reference cannot
    describe two different handoffs.
    """
    return ContinuationRecord(
        pk=record.pk,
        session_id=record.session_id,
        generation=handoff.incoming_generation,
        artifact_reference=continuation_artifact_reference(
            record, handoff.outgoing_generation
        ),
        created_at=at,
    )


class ContinuationStore(Protocol):
    """The three State_Store operations a handoff performs, stated as their conditions.

    The conditions *are* the guarantees, so they are written down here rather than left to each
    implementation to remember — the posture
    :class:`~control_plane.lifecycle.SessionLifecycleStore` and
    :class:`~control_plane.orchestrator.tasks.OrchestrationRowStore` both take. A structural type, so
    the offline suite drives the whole handoff against an in-memory store keyed as DynamoDB is, with
    no deployed resource and no network.

    Every item touched sits in the Session's own Tenant partition, so the confinement R11.3 requires
    applies without a second check. **There is no binding method**, which is R6.24 expressed as an
    absence: a handoff has no operation through which it could delete or rewrite the Affinity_Key
    binding.
    """

    def read_continuation(
        self, *, partition_key: str, sort_key: str
    ) -> Mapping[str, Any] | None:
        """Return the continuation record at this key, or `None` when there is none.

        Strongly consistent, for the reason
        :class:`~control_plane.api.lookup.SessionLookup` gives: this read decides whether the
        Sandbox about to be provisioned restores state, and an eventually consistent miss would
        start a continued Session empty while reporting success.
        """
        ...

    def record_continuation(self, record: ContinuationRecord) -> None:
        """`PutItem` the handoff record, refusing to overwrite one already at that key.

        `ConditionExpression: attribute_not_exists(pk)`.

        Raises:
            ContinuationAlreadyRecorded: an equivalent record is already there, which is a replayed
                handoff rather than a failure. The caller absorbs it.
        """
        ...

    def apply_continuation(self, handoff: ContinuationHandoff) -> None:
        """`UpdateItem` the row onto the incoming generation, dropping the outgoing Sandbox.

        `SET generation = :incoming, updatedAt = :at
        REMOVE sandboxHandle, sandboxId, connection, connectionPublishedAt` under
        `ConditionExpression: attribute_exists(pk) AND generation = :outgoing
        AND NOT lifecycleState IN (:terminated, :failed)`.

        The condition on `generation` is the idempotence: a replayed handoff finds the row already at
        the incoming generation and is refused rather than incrementing a second time.

        The four removals are one decision each and none of them is tidiness. The handle and
        identifier name a Sandbox that has just been terminated, so a `RefreshConnection` or a Reaper
        sweep reading them would act on something that no longer exists. The credential and its
        publication timestamp are generation *N*'s, and R9.16 already reads an absent credential as
        *not yet published* — so removing them makes a caller wait for the replacement's credential
        instead of being handed a dead one under the new generation, which is what stops a credential
        minted against the old generation from appearing to be current against the new Sandbox.

        `lifecycleState` is **not** written here. It is `CONTINUING` by then, moved by
        :mod:`control_plane.lifecycle`, which is also what refreshed the `tenant-state-index` sort
        key — so this write moves no indexed attribute and needs no derived key of its own.

        Raises:
            LifecycleConditionFailed: the row is absent, is already terminal, or is no longer at the
                outgoing generation.
        """
        ...


class SandboxQuiesce(Protocol):
    """Delivery of the `session.quiesce` message to a Session's Sandbox endpoint (R10.11).

    One method, in the shape :class:`~control_plane.credentials.ConnectionMint` established: this
    package decides *when* a Sandbox is asked to stop accepting new work, and the deployment holds
    the endpoint, the transport and the codec. `session.quiesce` is typed
    `orchestrator-to-runtime` in `protocol/messages.yaml` and carries an empty body, so there is
    nothing to pass but the Session whose endpoint and credential the row already holds.

    **It reports failure rather than raising it.** A Sandbox that will not take the message is being
    terminated in the very next step, and the archive does not depend on the message arriving:
    `/terminate` ends the Session's processes before it reads the tree, precisely so the archive is
    not a torn snapshot. Quiesce is what turns a request in flight at the ceiling into a clean
    refusal instead of a half-served one, so its failure is worth *recording* and is not worth
    abandoning a handoff for — abandoning one would leave a `CONTINUING` row with a live Sandbox and
    no step left to replace it.
    """

    def quiesce(self, record: SessionRecord) -> bool:
        """Ask this Session's Sandbox to stop accepting new work; report whether it acknowledged."""
        ...


@dataclass(frozen=True, slots=True)
class ContinuationHandoffs:
    """The handoff's two collaborators, and the three reads that depend on them.

    A collaborator that owns its own store, in the same posture as
    :class:`~control_plane.lifecycle.LifecycleReconciler`, so a deployment cannot end up with the
    handoff record going to one store and the generation increment to another.

    **There is no clock here and no write method.** The timestamps and the ordering of the writes
    belong to :meth:`~control_plane.orchestrator.tasks.SessionOrchestrator.continue_session`, which
    has the orchestration's one clock and is the module that may reach a Compute_Provider; what is
    here is what a handoff has to *read* or *derive* in order to decide anything.
    """

    store: ContinuationStore
    quiescer: SandboxQuiesce

    def start_configuration(self, record: SessionRecord) -> StartConfiguration:
        """Compose the run-configuration document this generation of this Session starts with.

        Both halves of the document, and each is present exactly when it has something to say:

        - `persist`, for every generation of a Session that declared continuation, naming *this*
          generation's archive reference and the declared path set. Without it the `/terminate` hook
          has no destination and a handoff at the ceiling would have nothing to hand over — which is
          why it is written at generation 1 and not first written at the ceiling.
        - `restore`, only for a generation a handoff recorded a reference for. Its absence is
          generation 1, or a Session whose handoff never got as far as recording one.

        A Session with continuation disabled gets neither, and therefore an empty
        :class:`StartConfiguration`. Nothing here composes `exposedPorts` or `endpointUrlTemplate`:
        those are the run hook's own configuration and belong to the tasks that own them, and a
        document this module wrote them into would be a second source for values the Session row
        already carries.

        The document is rendered with sorted keys, a sorted and de-duplicated path set, and no
        whitespace, so one row composes one byte string. That is what lets R7.11's two delivery paths
        be compared on the same logical input, and it keeps the document at the smallest size the
        provider's declared ceiling has to carry.
        """
        if not record.continuation_enabled:
            return StartConfiguration()

        document: dict[str, Any] = {}
        restore = self.restore_reference(record)
        if restore is not None:
            document[RESTORE_KEY] = {REFERENCE_KEY: restore}
        document[PERSIST_KEY] = {
            REFERENCE_KEY: continuation_artifact_reference(record, record.generation),
            # Sorted and de-duplicated, which is the normal form the reader of this document produces
            # anyway. Writing it already normalised means the declared set is one value on both sides
            # of the boundary rather than two renderings that a comparison would have to normalise.
            PATHS_KEY: sorted(set(record.continuation_paths)),
        }
        return StartConfiguration(
            document=json.dumps(document, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        )

    def restore_reference(self, record: SessionRecord) -> str | None:
        """The archive this generation restores from, or `None` when it has none to restore.

        Read from the continuation record written under this generation rather than derived from
        `generation - 1`, so a restore is attempted only where a handoff recorded one; see the module
        docstring.

        Raises:
            ItemShapeError: the stored record is malformed, which is a defect in this system rather
                than an answer about the Session, and is refused rather than read as "nothing to
                restore".
        """
        item = self.store.read_continuation(
            partition_key=record.pk,
            sort_key=continuation_sort_key(record.session_id, record.generation),
        )
        if item is None:
            return None
        return ContinuationRecord.from_item(item).artifact_reference

    def applied_handoff(self, record: SessionRecord) -> ContinuationRecord | None:
        """The handoff that already moved this row onto its current generation, if one did.

        This is how a replayed `Continue` is recognised, and it has to be recognised *before* the
        outgoing handle is read: :meth:`ContinuationStore.apply_continuation` drops the handle, so a
        replay after it succeeded has no Sandbox to name and would otherwise be refused as a row out
        of order — failing a Session whose handoff in fact completed.

        The signature of an applied handoff is two facts that only that write produces together: the
        row is `CONTINUING`, and it carries no Sandbox handle. Both are checked, and then the
        continuation record for the current generation is what confirms it — a row in that shape
        without one is not a completed handoff and is left to be refused as the defect it is.

        This is a read followed by a decision, which elsewhere in this design would be the wrong shape.
        It is sound here because the only concurrency is a *sequential* retry of one task by one
        execution: there is no second writer to race, and the write that follows carries its own
        condition on the generation regardless.
        """
        if (
            record.lifecycle_state is not LifecycleState.CONTINUING
            or record.sandbox_handle is not None
        ):
            return None
        item = self.store.read_continuation(
            partition_key=record.pk,
            sort_key=continuation_sort_key(record.session_id, record.generation),
        )
        return None if item is None else ContinuationRecord.from_item(item)
