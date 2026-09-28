# kiro-classification: public
"""The duration-ceiling handoff: what survives it, its ordering, and its idempotence (R10.11, R6.24).

Deterministic throughout. Property 8 — *continuation preserves the declared path set and nothing
else*, quantified over drawn path sets and drawn filesystem trees — is task 9.6's own file and owns
that number; what this file establishes is the mechanism those drawn cases will be quantified over,
and the two claims a property test cannot make on its own:

- **The Affinity_Key binding is not written on this path.** Asserted twice over. Once behaviourally,
  by driving a handoff and finding the binding item still present and still naming the same Session.
  Once structurally, by asserting that :class:`~control_plane.orchestrator.ContinuationHandoff` has no
  field and :class:`~control_plane.orchestrator.ContinuationStore` no method through which a binding
  could be reached at all — which is what makes R6.24 a property of the shapes rather than of the
  order somebody wrote the steps in.
- **The document this module composes is the document the runtime parses.** `control_plane/` imports
  nothing from `runtime/` by design, so the four run-configuration key names are spelled on both
  sides of a boundary neither may cross. A test may cross it, and
  :func:`test_the_composed_document_is_the_one_the_runtime_parses` is the only thing keeping the two
  spellings in step — the same job one assertion in `tests/test_connection_credentials.py` does for
  the Sandbox_Protocol control port.

The harness, the store double and the real `local-firecracker` provider are imported from
`tests/test_control_plane_orchestrator.py` rather than restated, so the conditions asserted here are
the ones that file already holds to the design and the Sandbox torn down by a handoff is one that
really existed.
"""

from __future__ import annotations

import json
from dataclasses import fields, replace
from typing import Any, Final

import pytest

from control_plane.lifecycle import LifecycleConditionFailed
from control_plane.orchestrator import (
    CONTINUATION_ARTIFACT_ID,
    CONTINUATION_REASON,
    ContinuationHandoff,
    ContinuationHandoffs,
    ContinuationNotEnabled,
    ContinuationStore,
    OrchestratorState,
    SandboxNotRecorded,
    StartConfiguration,
    continuation_artifact_reference,
    handle_of,
    handoff_for,
)
from control_plane.orchestrator.continuation import (
    PATHS_KEY,
    PERSIST_KEY,
    REFERENCE_KEY,
    RESTORE_KEY,
)
from control_plane.providers.base import SandboxHandle, SandboxState
from control_plane.state.keys import binding_sort_key, continuation_sort_key
from control_plane.state.records import (
    ContinuationRecord,
    LifecycleState,
    SessionRecord,
)
from runtime.run_config import parse_configuration
from tests.test_control_plane_lifecycle import DIGEST, SESSION_ID
from tests.test_control_plane_orchestrator import (
    APPLY_CONTINUATION,
    RECORD_CONTINUATION,
    Harness,
    harness,
    seated_record,
)

#: The declared continuation path set of every Session below. Two entries, both relative to the
#: configured filesystem root, because R10.11's path set is what the handoff carries and an empty one
#: would make "the declared set survived" vacuously true. Deliberately *not* in sorted order, so the
#: normal form the document carries is asserted rather than accidentally satisfied.
CONTINUATION_PATHS: Final = ("work", "state/db.sqlite")

#: The same set as the document and the runtime's parser both normalise it.
NORMALISED_PATHS: Final = tuple(sorted(CONTINUATION_PATHS))


def continuing(
    *, paths: tuple[str, ...] = CONTINUATION_PATHS, **overrides: Any
) -> SessionRecord:
    """A Session row that declared continuation, with a path set on it."""
    return replace(
        seated_record(),
        continuation_enabled=True,
        continuation_paths=paths,
        **overrides,
    )


# --- what survives, and what is replaced -----------------------------------------------------------


def test_the_handoff_replaces_the_sandbox_and_keeps_the_session() -> None:
    """The Session identifier is stable; the Sandbox, its handle and its generation are not."""
    setup = harness(record=continuing())
    setup.forward_path()
    outgoing = setup.row()
    assert outgoing.sandbox_id is not None

    result = continued_result = setup.run(OrchestratorState.CONTINUE)

    row = setup.row()
    assert row.session_id == outgoing.session_id == SESSION_ID
    assert row.generation == outgoing.generation + 1
    assert row.lifecycle_state is LifecycleState.CONTINUING
    assert row.state_reason == CONTINUATION_REASON
    # The outgoing Sandbox is gone from the row, so nothing reads a handle for a Sandbox that was
    # just terminated.
    assert row.sandbox_handle is None
    assert row.sandbox_id is None
    assert result["outgoingGeneration"] == outgoing.generation
    assert continued_result["generation"] == row.generation
    assert result["sandboxState"] in {"TERMINATING", "TERMINATED"}


def test_the_replacement_restores_the_declared_set_and_the_outgoing_credential_is_dropped() -> (
    None
):
    """R10.11's two halves, and the reason the old credential cannot appear current (point 3)."""
    setup = harness(record=continuing())
    setup.forward_path()
    outgoing = setup.row()
    assert outgoing.connection is not None

    setup.run(OrchestratorState.CONTINUE)

    handed_off = setup.row()
    # R9.16 reads an absent credential as *not yet published*, so a caller waits for the
    # replacement's rather than being handed generation N's against generation N+1.
    assert handed_off.connection is None
    assert handed_off.connection_published_at is None

    setup.run(OrchestratorState.PROVISION)
    setup.run(OrchestratorState.CLAIM_SANDBOX)
    setup.run(OrchestratorState.AWAIT_READY)
    setup.run(OrchestratorState.PUBLISH_CREDENTIAL)

    replacement = setup.row()
    assert replacement.generation == outgoing.generation + 1
    assert replacement.lifecycle_state is LifecycleState.RUNNING
    assert replacement.connection is not None
    # A different Sandbox, so a credential scoped to the outgoing one reaches nothing.
    assert replacement.sandbox_id != outgoing.sandbox_id
    assert replacement.connection != outgoing.connection


def test_the_replacement_takes_a_fresh_claim_and_the_outgoing_one_is_not_reopened() -> (
    None
):
    """R11.10: one Sandbox belongs to one Session ever, so a handoff claims rather than reuses."""
    setup = harness(record=continuing())
    setup.forward_path()
    outgoing_claims = set(dict(setup.claims.items))

    setup.run(OrchestratorState.CONTINUE)
    setup.run(OrchestratorState.PROVISION)
    setup.run(OrchestratorState.CLAIM_SANDBOX)

    claims = set(dict(setup.claims.items))
    assert len(claims) == len(outgoing_claims) + 1
    assert outgoing_claims < claims


def test_the_binding_is_untouched_by_the_handoff() -> None:
    """R6.24: the binding names the Session identifier, which a continuation does not change."""
    setup = harness(record=continuing())
    setup.forward_path()

    result = setup.run(OrchestratorState.CONTINUE)

    assert result["bindingRetained"] is True
    assert result["sessionId"] == SESSION_ID
    assert setup.store.holds_binding(seated_record(), DIGEST)
    # No step deleted and re-created it either: the binding item is the one seating wrote.
    binding = setup.store.read_continuation(
        partition_key=setup.row().pk, sort_key=binding_sort_key(DIGEST)
    )
    assert binding is not None
    assert binding["sessionId"] == SESSION_ID


def test_no_write_type_or_store_method_can_reach_the_binding() -> None:
    """The structural half of R6.24: there is nowhere for a binding write to live on this path."""
    assert {declared.name for declared in fields(ContinuationHandoff)} == {
        "partition_key",
        "sort_key",
        "outgoing_generation",
        "updated_at",
    }
    assert not [
        declared
        for declared in fields(ContinuationHandoff)
        if "Binding" in str(declared.type) or "LifecycleState" in str(declared.type)
    ]
    methods = {
        name for name in vars(ContinuationStore) if not name.startswith("_")
    } | set(getattr(ContinuationStore, "__protocol_attrs__", set()))
    assert methods == {
        "read_continuation",
        "record_continuation",
        "apply_continuation",
    }


# --- ordering --------------------------------------------------------------------------------------


def test_the_row_says_continuing_before_the_outgoing_sandbox_is_torn_down() -> None:
    """Step 1 before step 3, so an operator reads the handoff while it is happening (R14.2)."""
    setup = harness(record=continuing())
    setup.forward_path()
    setup.store.trace.clear()

    setup.run(OrchestratorState.CONTINUE)

    # Both continuation writes landed on a row that already said CONTINUING, which is only possible
    # if the lifecycle write preceded them and the teardown between them.
    assert setup.store.state_at(APPLY_CONTINUATION) == LifecycleState.CONTINUING.value
    assert setup.store.operations()[0] == "advance"


def test_a_session_settled_underneath_the_handoff_loses_no_sandbox() -> None:
    """The `CONTINUING` write is first precisely so a lost race costs nothing.

    A Reaper that settled this Session while the governing loop was deciding leaves a terminal row.
    The handoff's first act is refused by that row's own condition, and it is refused *before* the
    quiesce and *before* `provider.terminate`, so nothing has been done to the Sandbox that whoever
    owns the teardown now is going to stop.
    """
    setup = harness(record=continuing())
    setup.forward_path()
    handle = setup.orchestrator.provider.discover({})[0].handle
    setup.store.items[(setup.row().pk, setup.row().sort_key)]["lifecycleState"] = (
        LifecycleState.TERMINATED.value
    )

    with pytest.raises(LifecycleConditionFailed):
        setup.run(OrchestratorState.CONTINUE)

    assert setup.quiescer.quiesced == []
    # Still allocated, so the handoff stopped before it touched it.
    assert setup.provider.release_check(handle) != []


def test_the_handoff_record_names_an_archive_the_terminate_hook_was_asked_to_write() -> (
    None
):
    """Step 4 after step 3, and keyed under the generation that restores from it."""
    setup = harness(record=continuing())
    setup.forward_path()
    outgoing = setup.row()

    result = setup.run(OrchestratorState.CONTINUE)

    reference = continuation_artifact_reference(outgoing, outgoing.generation)
    assert result["artifactReference"] == reference
    assert reference.endswith(f"/{outgoing.generation}/{CONTINUATION_ARTIFACT_ID}")

    item = setup.store.read_continuation(
        partition_key=outgoing.pk,
        sort_key=continuation_sort_key(SESSION_ID, outgoing.generation + 1),
    )
    assert item is not None
    recorded = ContinuationRecord.from_item(item)
    assert recorded.generation == outgoing.generation + 1
    assert recorded.artifact_reference == reference
    # And it is the reference the outgoing Sandbox's own `/terminate` hook was configured to write,
    # which is what makes the two halves one object rather than two that happen to agree.
    document = parse_configuration(
        ContinuationHandoffs(store=setup.store, quiescer=setup.quiescer)
        .start_configuration(outgoing)
        .document
    )
    assert document.persist is not None
    assert document.persist.reference == reference


def test_the_quiesce_precedes_the_teardown_and_a_refusal_does_not_abandon_it() -> None:
    """A Sandbox that will not stop accepting work is terminated in the next step regardless."""
    setup = harness(record=continuing())
    setup.forward_path()

    result = setup.run(OrchestratorState.CONTINUE)
    assert result["quiesced"] is True
    assert setup.quiescer.quiesced == [(SESSION_ID, 1)]

    unreachable = harness(record=continuing(), acknowledges_quiesce=False)
    unreachable.forward_path()

    refused = unreachable.run(OrchestratorState.CONTINUE)
    assert refused["quiesced"] is False
    # Recorded, not fatal: the handoff still completed, so no CONTINUING row is left with a live
    # Sandbox and no step remaining to replace it.
    assert refused["applied"] is True
    assert unreachable.row().generation == 2


# --- idempotence ---------------------------------------------------------------------------------


def test_a_replayed_handoff_produces_one_new_sandbox_and_one_increment() -> None:
    """Step Functions may retry the task; a replay must not advance the Session twice."""
    setup = harness(record=continuing())
    setup.forward_path()

    first = setup.run(OrchestratorState.CONTINUE)
    replayed = setup.run(OrchestratorState.CONTINUE)

    assert first["applied"] is True
    assert first["handoffRecorded"] is True
    assert replayed["applied"] is False
    assert replayed["handoffRecorded"] is False
    # The replay reports the generation the row really holds and the archive the completed handoff
    # really recorded, rather than the ones it would have written.
    assert replayed["generation"] == first["generation"] == 2
    assert replayed["outgoingGeneration"] == first["outgoingGeneration"] == 1
    assert replayed["artifactReference"] == first["artifactReference"]
    # No provider was asked, because the row no longer names a Sandbox to ask about.
    assert replayed["sandboxState"] is None
    assert setup.row().generation == 2
    assert [
        generation
        for name, generation in setup.store.trace
        if name == RECORD_CONTINUATION
    ] == ["2"]

    setup.run(OrchestratorState.PROVISION)
    # Exactly one *live* Sandbox for the Session, whatever the replay did: this task provisions
    # nothing, and `Provision` is reached once per traversal of the governing choice. Asserted against
    # the provider's own inventory rather than a call log; the outgoing Sandbox is still listed and
    # terminated, which is what a Reaper sweep would also see.
    live = [
        found
        for found in setup.provider.discover({})
        if found.state
        not in {SandboxState.TERMINATING, SandboxState.TERMINATED, SandboxState.FAILED}
    ]
    assert len(live) == 1
    assert live[0].handle.sandbox_id == setup.row().sandbox_id


def test_a_replay_between_the_teardown_and_the_increment_converges() -> None:
    """The mid-flight replay: the archive is recorded but the row is still on the old generation.

    This is the window the two conditional writes exist for. `provider.terminate` is idempotent, the
    handoff record absorbs, and the generation increment is the one thing left to do.
    """
    setup = harness(record=continuing())
    setup.forward_path()
    record = setup.row()
    handoff = handoff_for(record, at=setup.clock.at)
    setup.store.record_continuation(
        ContinuationRecord(
            pk=record.pk,
            session_id=SESSION_ID,
            generation=handoff.incoming_generation,
            artifact_reference=continuation_artifact_reference(record, 1),
            created_at=setup.clock.at,
        )
    )
    setup.orchestrator.provider.terminate(record_handle(setup))

    resumed = setup.run(OrchestratorState.CONTINUE)

    assert resumed["handoffRecorded"] is False
    assert resumed["applied"] is True
    assert resumed["generation"] == 2
    assert setup.row().generation == 2
    assert setup.row().sandbox_handle is None
    assert [
        generation
        for name, generation in setup.store.trace
        if name == RECORD_CONTINUATION
    ] == ["2"]


def test_a_replayed_handoff_leaves_the_recorded_archive_alone() -> None:
    """The first record for a generation stands, so `createdAt` describes the handoff not the replay."""
    setup = harness(record=continuing())
    setup.forward_path()
    setup.run(OrchestratorState.CONTINUE)
    key = continuation_sort_key(SESSION_ID, 2)
    first = setup.store.read_continuation(partition_key=setup.row().pk, sort_key=key)

    setup.clock.at += 5_000
    setup.run(OrchestratorState.CONTINUE)

    assert setup.store.read_continuation(
        partition_key=setup.row().pk, sort_key=key
    ) == (first)


def test_a_second_handoff_from_the_replacement_advances_one_generation_further() -> (
    None
):
    """Two ceilings in one Session's life: the generations and the archives do not collide."""
    setup = harness(record=continuing())
    setup.forward_path()
    setup.run(OrchestratorState.CONTINUE)
    setup.run(OrchestratorState.PROVISION)
    setup.run(OrchestratorState.CLAIM_SANDBOX)
    setup.run(OrchestratorState.AWAIT_READY)
    setup.run(OrchestratorState.PUBLISH_CREDENTIAL)

    second = setup.run(OrchestratorState.CONTINUE)

    assert second["outgoingGeneration"] == 2
    assert setup.row().generation == 3
    assert second["artifactReference"] != continuation_artifact_reference(
        setup.row(), 1
    )
    assert (
        setup.store.read_continuation(
            partition_key=setup.row().pk, sort_key=continuation_sort_key(SESSION_ID, 3)
        )
        is not None
    )


# --- the run-configuration document ----------------------------------------------------------------


def test_the_composed_document_is_the_one_the_runtime_parses() -> None:
    """The one assertion holding the two spellings of four key names in step.

    `control_plane/` imports nothing from `runtime/`, so the document keys are written twice. A test
    may import both sides, and this is the only thing that would notice a rename on either.
    """
    setup = harness(record=continuing())
    record = setup.row()
    handoffs = ContinuationHandoffs(store=setup.store, quiescer=setup.quiescer)
    first_archive = continuation_artifact_reference(record, 1)

    # Generation 1: a destination to archive to and nothing to restore. The key names are the
    # control-plane spellings, asserted as such...
    document = handoffs.start_configuration(record).document
    assert json.loads(document) == {
        PERSIST_KEY: {
            REFERENCE_KEY: first_archive,
            PATHS_KEY: list(NORMALISED_PATHS),
        }
    }
    # ...and the runtime's own parser is what says they are the names it reads. A rename on either
    # side turns one of these two halves into a failure.
    first = parse_configuration(document)
    assert first.restore is None
    assert first.persist is not None
    assert first.persist.reference == first_archive
    assert first.persist.paths == NORMALISED_PATHS

    setup.store.record_continuation(
        ContinuationRecord(
            pk=record.pk,
            session_id=SESSION_ID,
            generation=2,
            artifact_reference=first_archive,
            created_at=record.created_at,
        )
    )
    continued = handoffs.start_configuration(replace(record, generation=2)).document
    assert json.loads(continued) == {
        RESTORE_KEY: {REFERENCE_KEY: first_archive},
        PERSIST_KEY: {
            REFERENCE_KEY: continuation_artifact_reference(record, 2),
            PATHS_KEY: list(NORMALISED_PATHS),
        },
    }
    second = parse_configuration(continued)
    assert second.restore is not None
    assert second.restore.reference == first_archive
    assert second.persist is not None
    assert second.persist.reference == continuation_artifact_reference(record, 2)
    # The persist destination of one generation is never the restore source of the same one, which is
    # what the generation segment in the artifact layout exists for.
    assert second.persist.reference != second.restore.reference


def test_a_session_that_declared_no_continuation_gets_no_document_and_no_handoff() -> (
    None
):
    """Continuation is opt-in per Session, and the opt-out is visible in both directions."""
    setup = harness()
    handoffs = ContinuationHandoffs(store=setup.store, quiescer=setup.quiescer)

    assert handoffs.start_configuration(setup.row()) == StartConfiguration()

    setup.forward_path()
    with pytest.raises(ContinuationNotEnabled):
        setup.run(OrchestratorState.CONTINUE)
    assert setup.row().generation == 1
    assert setup.row().sandbox_handle is not None


def test_the_document_names_the_declared_set_and_nothing_else() -> None:
    """Property 8's "and nothing else", as far as a deterministic test can state it.

    The path set in the document is the declared set exactly. What the *archive* then contains is
    `runtime.persist`'s claim and Property 8's quantified assertion; what is asserted here is that no
    step between the Session row and the `/terminate` hook widens the set.
    """
    setup = harness(record=continuing(paths=("only/this",)))
    handoffs = ContinuationHandoffs(store=setup.store, quiescer=setup.quiescer)

    document = handoffs.start_configuration(setup.row()).document

    persist = parse_configuration(document).persist
    assert persist is not None
    assert persist.paths == ("only/this",)
    # Rendered with sorted keys and no whitespace, so one row composes one byte string and R7.11's
    # two delivery paths can be compared on the same logical input.
    assert document == handoffs.start_configuration(setup.row()).document
    assert b" " not in document
    assert list(_keys(document)) == sorted(_keys(document))


# --- the shapes ------------------------------------------------------------------------------------


def test_a_handoff_derives_its_incoming_generation_rather_than_carrying_one() -> None:
    """The value written and the value the condition tests are one number and one increment."""
    record = continuing(generation=4)
    handoff = handoff_for(record, at=1_700_000_000_000)

    assert handoff.outgoing_generation == 4
    assert handoff.incoming_generation == 5
    assert handoff.partition_key == record.pk
    assert handoff.sort_key == record.sort_key
    assert "incoming_generation" not in {
        declared.name for declared in fields(ContinuationHandoff)
    }


def test_a_generation_that_never_existed_is_not_one_a_handoff_can_leave() -> None:
    """A Session's generation starts at 1, so 0 and below name nothing."""
    row = seated_record()
    for generation in (0, -1):
        with pytest.raises(ValueError, match="generation starts at 1"):
            ContinuationHandoff(
                partition_key=row.pk,
                sort_key=row.sort_key,
                outgoing_generation=generation,
                updated_at=0,
            )


def test_a_handoff_from_a_row_with_no_sandbox_is_refused() -> None:
    """There is no Sandbox to hand off from, which is out of order rather than operational."""
    setup = harness(record=continuing())

    with pytest.raises(SandboxNotRecorded):
        setup.run(OrchestratorState.CONTINUE)

    assert setup.row().generation == 1


def record_handle(setup: Harness) -> SandboxHandle:
    """The provider handle the Session row currently names."""
    return handle_of(setup.row(), OrchestratorState.CONTINUE)


def _keys(document: bytes) -> list[str]:
    """The document's own top-level keys, in the order they were rendered."""
    return list(json.loads(document))
