# kiro-classification: public
"""The `/run` hook's body: read the configuration, generate the values, restore, apply.

`runtime.hooks` sequences the four hooks against the readiness gate and delegates their substance
to `LifecycleActions`. This module is that implementation, for `/run`. The gate transitions are
not repeated here and must not be: the hook opens the gate after this returns and fails it closed
if this raises, which is both halves of R7.8, and an action that touched the gate would be able to
break a guarantee it does not own.

## The order is the design's, and each step depends on the one before

1. **Read the configuration** — inline, or fetched from the State_Store when the payload carries a
   reference instead (R7.11). `runtime.run_config` owns the decision and the document.
2. **Generate every per-Session unique value** (R7.12), inside this call. `runtime.session_values`
   owns them and explains why the generation cannot be anywhere else.
3. **Restore previously persisted state**, when the configuration names some (R13.4), which
   happens before readiness because this whole method does. A failure raises `RestorationFailure`
   carrying the identifying reason R13.7 requires, and `runtime.hooks` turns it into the non-200.
4. **Apply** the configuration to the components that hold per-Session state.

## Applying is the last thing, and it happens all at once

Steps 1 to 3 compute and write, but nothing they do is *visible* to a protocol request: the
document is a local value, the generated values are local, and the restored files are behind a
handler that has not opened. Step 4 is the one that publishes — it configures the exposed-port set
and the endpoint routing template, after which `port.expose` starts answering — so it is deferred
to the end and performed in one go.

That ordering matters for the failure case rather than the success case. A configuration applied
field by field as it was read would leave a Sandbox whose ports were configured and whose state
was not restored, and the readiness gate would then hold that Sandbox `FAILED` while its
components carried half a Session's configuration. Nothing could observe it today, because a
`FAILED` gate admits no request; the reason to avoid it anyway is that "partially applied" is a
state no later task should have to reason about, and deferring the publish means it never exists.

The second consequence is the R7.8 prohibition, which is the sentence that is easiest to satisfy
by accident and easiest to break by accident: *before* `/run`, no per-Session configuration is
applied. It holds here because there is no other code path that configures anything —
`configuration` and `values` are None until this method succeeds, and both are readable so that a
test can assert the absence rather than infer it.

## The other three hooks

`/suspend`, `/resume` and `/terminate` have their substance in three modules of their own, for the
same reason `/run`'s is split across `runtime.run_config`, `runtime.session_values` and
`runtime.restore`: what each hook *does* is a body of work with its own failure vocabulary, and what
this class does is bind those bodies to the components one Sandbox holds. `runtime.quiesce`,
`runtime.egress_identity` and `runtime.persist` are those three, and each one's docstring is where
its requirement is argued.

None of the three returns quietly when it cannot do its job. A `quiesce_and_flush` that did nothing
would let `/suspend` return 200 having flushed nothing, which is a false statement about durability
of exactly the kind R7.9 exists to prevent, and a silent no-op is much harder to notice than a
raised exception. The same reading applies to the other two: `runtime.hooks` turns an exception from
an action into a non-200, so a hook that could not do what its requirement asks says so.

## What `/suspend` quiesces and what `/terminate` ends

The asymmetry is deliberate and it is the design's, not a convenience:

- **`/suspend` ends nothing.** It flushes and closes connections, and it leaves the Session's
  processes running and its pseudo-terminals open. A suspended Session retains its filesystem *and
  memory* state and restores both on resume (R13.2), and a resume can be triggered by nothing more
  than a request arriving at the endpoint (R10.5). Killing the agent's long-running build here would
  make auto-resume a promise about a Sandbox that had been quietly emptied.
- **`/terminate` ends everything, first.** Background children are killed and reaped and every
  terminal is closed *before* the archive is read, because a process still writing would make the
  artifact a torn snapshot of a tree that never existed at any single moment. This is also where
  those shutdowns have to happen at all: `ProcessManager` and `TerminalManager` attach their reaping
  tasks to the loop that spawned the children, which is the application's own loop, and this method
  runs on it.
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from typing import Final, Protocol

from runtime.egress_identity import EgressIdentity, EgressIdentityManager
from runtime.filesystem import ConfinedRoot
from runtime.observability import SessionLogEmitter
from runtime.persist import PersistedArtifact, StateStoreWriter, persist_state
from runtime.ports import ExposedPorts, TemplatePortRouting
from runtime.quiesce import (
    DEFAULT_QUIESCE_DEADLINE_SECONDS,
    OutboundConnections,
    QuiesceReport,
    quiesce,
)
from runtime.restore import restore_state
from runtime.run_config import (
    MAX_RUN_CONFIG_BYTES,
    ConfigurationError,
    RunConfiguration,
    RunConfigurationReader,
    StateStoreReader,
)
from runtime.session_values import SessionValues

__all__ = ["RunningWork", "SandboxLifecycle"]

#: How long `/terminate` waits for the Session's processes and terminals to end before giving up on
#: them and archiving anyway. Bounded because a child ignoring `SIGKILL` — blocked in an
#: uninterruptible syscall, which a Sandbox can arrange — would otherwise hold the hook open and
#: leave a billable Sandbox allocated, which is the same failure the artifact deadline exists to
#: avoid. Losing the wait costs a possibly-torn artifact; losing the hook costs the Sandbox.
SHUTDOWN_DEADLINE_SECONDS: Final = 15.0


class RunningWork(Protocol):
    """Something holding the Session's own running work, which `/terminate` ends.

    `runtime.process.ProcessManager` and `runtime.terminal.TerminalManager` both satisfy it
    structurally — the method name is theirs — so neither implements an interface that exists for
    this module's convenience. A Protocol rather than the two concrete types because
    `runtime.terminal` imports `pty`, `termios` and `fcntl` and therefore does not import on every
    platform; naming it structurally is what keeps this module importable where that one is not.
    """

    async def shutdown(self) -> None:
        """End every process or session this holds, and reap it."""
        ...


class SandboxLifecycle:
    """The hook bodies for one Sandbox_Runtime process.

    Satisfies `runtime.hooks.LifecycleActions` structurally rather than by inheritance, which is
    the stance that Protocol takes about its implementations: `create_app(actions=...)` is where
    the four method names and signatures are checked against the seam.
    """

    def __init__(
        self,
        *,
        ports: ExposedPorts | None = None,
        filesystem_root: ConfinedRoot | None = None,
        state_store: StateStoreReader | None = None,
        state_writer: StateStoreWriter | None = None,
        egress_identity: EgressIdentityManager | None = None,
        outbound: Sequence[OutboundConnections] = (),
        running_work: Sequence[RunningWork] = (),
        emitter: SessionLogEmitter | None = None,
        max_payload_bytes: int = MAX_RUN_CONFIG_BYTES,
        quiesce_deadline_seconds: float = DEFAULT_QUIESCE_DEADLINE_SECONDS,
        shutdown_deadline_seconds: float = SHUTDOWN_DEADLINE_SECONDS,
    ) -> None:
        """Bind the components this Sandbox's hooks act on.

        Every collaborator is optional and absent means "this deployment has none", which is a
        truthful configuration rather than a convenient default. A runtime with no `ports` applies
        no port set; one with no `filesystem_root` or no `state_store` cannot restore state and
        refuses a configuration that asks it to, naming which of the two it is missing, rather
        than returning 200 having quietly skipped R13.4.

        The same reading extends to the three collaborators the other hooks need, and it is not
        uniform, because the requirements are not:

        - `state_writer` absent is a runtime that cannot write artifacts, and it refuses a
          configuration whose `persist` asks it to. A configuration with no `persist` asks for
          nothing and gets nothing, which is R13.3 satisfied by there being no configured artifacts.
        - `egress_identity` absent is a runtime that cannot serve `/resume` at all, and it says so
          rather than returning 200. R7.10 is unconditional and the Family B identity is not an
          optional part of the architecture: every deployed Sandbox reaches the network through the
          Egress_Controller, so a runtime with nothing to refresh is misconfigured rather than
          minimally configured.
        - `outbound` and `running_work` empty are both ordinary. A deployment holds as many
          connection holders and work registries as it composed, and none is a valid number of each.
        - `emitter` absent is a runtime that emits no lifecycle records. Where one is present it is
          the same object `runtime.app` gave the hooks, and this class's only use of it is to bind
          the Runtime instance identifier once the values exist (R7.12, R14.1) — the hooks emit,
          this binds. Only one of the two can: the identifier is generated inside this method.
        """
        self._ports = ports
        self._filesystem_root = filesystem_root
        self._state_store = state_store
        self._state_writer = state_writer
        self._egress_identity = egress_identity
        self._outbound = tuple(outbound)
        self._running_work = tuple(running_work)
        self._emitter = emitter
        self._quiesce_deadline_seconds = quiesce_deadline_seconds
        self._shutdown_deadline_seconds = shutdown_deadline_seconds
        self._reader = RunConfigurationReader(
            source=state_store, max_payload_bytes=max_payload_bytes
        )
        self._configuration: RunConfiguration | None = None
        self._values: SessionValues | None = None
        self._quiesced: QuiesceReport | None = None
        self._persisted: PersistedArtifact | None = None
        self._shutdown_overran: tuple[str, ...] = ()

    @property
    def configuration(self) -> RunConfiguration | None:
        """The applied configuration, or None before `/run` has applied one (R7.8)."""
        return self._configuration

    @property
    def values(self) -> SessionValues | None:
        """The per-Session values this Sandbox generated, or None before `/run` (R7.12)."""
        return self._values

    @property
    def quiesced(self) -> QuiesceReport | None:
        """What the last `/suspend` flushed and closed, or None before one succeeded (R7.9)."""
        return self._quiesced

    @property
    def egress_identity(self) -> EgressIdentity | None:
        """The Family B identity in effect, or None before a `/resume` refreshed one (R7.10)."""
        return None if self._egress_identity is None else self._egress_identity.identity

    @property
    def persisted(self) -> PersistedArtifact | None:
        """The artifact `/terminate` wrote, or None where none was configured (R13.3)."""
        return self._persisted

    async def apply_configuration(self, payload: bytes) -> None:
        """Apply the per-Session configuration the run hook payload delivers.

        Raises:
            RestorationFailure: state restoration failed, carrying the identifying reason (R13.7).
            ConfigurationError: the payload is not a configuration this runtime can apply.
        """
        if self._configuration is not None:
            # Unreachable through the gate, which refuses a second `/run`. Kept because the
            # values must be generated exactly once and this object outlives one hook call: a
            # second application would mint a second set and void every handle issued under the
            # first, so it is refused here as well as there.
            raise ConfigurationError(
                "this Sandbox has already applied its per-Session configuration; the "
                "per-Session unique values are generated exactly once (R7.12)"
            )

        configuration = await self._reader.read(payload)
        values = SessionValues.generate()
        if configuration.restore is not None:
            await restore_state(
                configuration.restore,
                root=self._require_root(),
                source=self._require_state_store(),
            )
        self._apply(configuration)
        self._configuration = configuration
        self._values = values
        if self._emitter is not None:
            # Last, with the publish, and for the same reason: an identifier bound before the
            # configuration was applied would appear on a record describing a `/run` that then
            # failed, which would attribute this generation's stream to a writer that never
            # served anything. The identifier is generated here (R7.12) and this is the only
            # moment at which it both exists and belongs to a Sandbox that is about to serve.
            self._emitter.bind_instance(values.instance_id)

    async def quiesce_and_flush(self) -> None:
        """Flush pending filesystem writes and close outbound connections (R7.9).

        The gate is already closed and drained: `runtime.hooks` does that first, which is R7.9's
        ordering and the only thing that makes this flush mean anything. Nothing is stopped or
        reaped here — see the module docstring for why a suspended Sandbox keeps its processes.

        Raises:
            QuiesceFailure: the flush or one of the closes did not complete.
        """
        self._quiesced = await quiesce(
            root=self._filesystem_root,
            outbound=self._outbound,
            deadline_seconds=self._quiesce_deadline_seconds,
        )

    async def refresh_egress_identity(self) -> None:
        """Refresh the Family B egress identity before the handler reopens (R7.10).

        Raises:
            ConfigurationError: this runtime has no egress identity to refresh.
            EgressRefreshFailure: the refresh did not produce an identity. The gate stays closed,
                so no request is served against a stale one.
        """
        if self._egress_identity is None:
            raise ConfigurationError(
                "this runtime has no egress identity manager, so the Family B identity R7.10 "
                "requires refreshing before /resume returns 200 cannot be refreshed"
            )
        values = self._values
        # An empty key rather than a separate arm: `EgressIdentityManager.refresh` already refuses
        # one, naming the `/resume`-before-`/run` case, and one refusal in one place is one sentence
        # for an operator to read instead of two that have to be kept saying the same thing.
        await self._egress_identity.refresh(
            private_key=b"" if values is None else values.egress_private_key
        )

    async def persist_artifacts(self) -> None:
        """End the Session's running work, then write the configured artifacts (R13.3).

        The shutdown happens whether or not artifacts are configured, and it happens first. A
        Session with no `persist` still has children to reap, and reaping them is not conditional on
        there being somewhere to write: leaving them running would leak processes out of a Sandbox
        the provider is about to tear down and, worse, out of every test that terminated one.

        Raises:
            ConfigurationError: artifacts are configured but this runtime cannot write them.
            ArtifactPersistFailure: the archive could not be written.
        """
        await self._end_running_work()
        configuration = self._configuration
        # `/terminate` on a Sandbox that never ran is admitted by the gate — it is the disposal path
        # for an allocated-but-unused Sandbox — so there may be no configuration at all here.
        request = None if configuration is None else configuration.persist
        if request is None:
            return
        self._persisted = await persist_state(
            request,
            root=self._require_root_for_persist(),
            destination=self._require_state_writer(),
        )

    async def _end_running_work(self) -> None:
        """Shut every work registry down, bounded, and report what would not end.

        Each registry is given the whole deadline rather than a share of it, because they are
        independent: a process manager whose child is wedged in an uninterruptible syscall should not
        cost the terminal manager its chance to close its pseudo-terminals. A registry that does not
        finish is reported and the hook continues, because the artifact write is the thing R13.3 asks
        for and abandoning it over a child that would not die would lose the Session's output to
        protect a teardown that is happening anyway.
        """
        overran: list[str] = []
        for work in self._running_work:
            try:
                async with asyncio.timeout(self._shutdown_deadline_seconds):
                    await work.shutdown()
            except TimeoutError:
                overran.append(type(work).__name__)
        # Not raised. See the docstring: the artifact is worth more than the tidiness, and the
        # provider's teardown ends these processes regardless. It is recorded so that a torn
        # artifact has an explanation attached to it rather than being a mystery.
        self._shutdown_overran = tuple(overran)

    @property
    def shutdown_overran(self) -> tuple[str, ...]:
        """Work registries `/terminate` gave up waiting for. Empty in the ordinary case."""
        return self._shutdown_overran

    def _apply(self, configuration: RunConfiguration) -> None:
        """Publish the configuration to the components that hold per-Session state."""
        if self._ports is None:
            if configuration.exposed_ports:
                raise ConfigurationError(
                    "the configuration declares exposed ports but this runtime has no "
                    "exposed-port registry to apply them to"
                )
            return
        template = configuration.endpoint_url_template
        if template is None:
            if configuration.exposed_ports:
                # A declared port with no way to address it is a configuration that promises
                # reachability it cannot deliver. `port.expose` would refuse every one of those
                # ports for want of routing, which is a confusing way to learn that the document
                # was incomplete.
                raise ConfigurationError(
                    "the configuration declares exposed ports but no endpoint URL template, "
                    "so no URL would reach any of them"
                )
            return
        try:
            routing = TemplatePortRouting(template)
        except ValueError as exc:
            raise ConfigurationError(str(exc)) from exc
        self._ports.configure(declared=configuration.exposed_ports, routing=routing)

    def _require_root(self) -> ConfinedRoot:
        if self._filesystem_root is None:
            raise ConfigurationError(
                "the configuration names previously persisted state to restore but this "
                "runtime has no configured filesystem root to restore it into (R13.4)"
            )
        return self._filesystem_root

    def _require_state_store(self) -> StateStoreReader:
        if self._state_store is None:
            raise ConfigurationError(
                "the configuration names previously persisted state to restore but this "
                "runtime has no State_Store reader to fetch it with (R13.4)"
            )
        return self._state_store

    def _require_root_for_persist(self) -> ConfinedRoot:
        if self._filesystem_root is None:
            raise ConfigurationError(
                "the configuration names Session output artifacts to write but this runtime "
                "has no configured filesystem root to read them from (R13.3)"
            )
        return self._filesystem_root

    def _require_state_writer(self) -> StateStoreWriter:
        if self._state_writer is None:
            raise ConfigurationError(
                "the configuration names Session output artifacts to write but this runtime "
                "has no State_Store writer to write them with (R13.3)"
            )
        return self._state_writer
