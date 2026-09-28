# kiro-classification: public
"""The Session-identifying log emitter: where a Sandbox's logs go, and what they may carry (R14.1).

R14.1 is one sentence with two obligations in it. The Sandbox_Runtime emits logs to CloudWatch
Logs, and it emits them "under a log group and stream that identify the Session". The design fixes
both names in its Observability table: the group is `/aws/sandbox/<env>` and the stream is
`<tenantId>/<sessionId>/<generation>`. This module is the sole producer of those two strings and
the record that travels under them.

## The naming is the requirement, so it has exactly one producer

A log stream name that a Sandbox composes one way and an operator reconstructs another way
identifies nothing. R14.3 is the reason that matters: correlating one Session's audit record, its
orchestration execution and its log stream is a documented procedure an operator performs by
*constructing* the stream name from the Session row, and the Control_Plane holds exactly three of
the values in it — Tenant, Session and generation. So `LogDestination.of` is the one function that
joins them, and everything that needs the name reads it from there.

That is also why the **Runtime instance identifier is not part of the name**, even though the
design's `/run` hook section describes it as "used in log stream naming". The identifier is
generated inside the MicroVM during `/run`
(`runtime.session_values`, R7.12), so no component outside the Sandbox can predict it — a stream
name containing it would be a name the correlation procedure could not construct, which is the one
thing the name exists to allow. The job that phrase describes is distinguishing two runtime
processes that wrote into the same stream, and this module does that job by carrying `instanceId`
as a field on every record instead. The Observability table's three-segment stream is the naming
R14.1 is discharged by; the identifier is how a reader tells writers apart within it.

## What a record may carry, and why that is an allow-list

A Sandbox runs Untrusted_Code. Its process output, its file contents, its argv and its environment
are all attacker-chosen, and the Sandbox also holds three secrets: the Family B private key, the
process-handle HMAC key, and — reaching it from the other side — the connection credential the
Control_Plane minted for its caller. A log line is the easiest way for any of those to leave the
boundary the rest of the architecture spends its effort maintaining, and it leaves *durably*, into
a log group an operator reads.

So the detail fields a record may carry are enumerated in `EMITTABLE_FIELDS` and a name outside
that set is **refused rather than dropped**. Refusing is the fail-closed answer to "may I log
this?": dropping the field would emit a record that silently said less than the caller asked for,
and the caller would learn its diagnostic was missing only by not finding it in production. The
consequence is that adding a field is a decision made here, in writing, once — which is the same
stance `runtime.run_config` takes on unknown configuration keys and for the same reason.

Two of those decisions are worth stating outright, because they are the ones that look arbitrary:

- **There is no field for process output, file content, a path, an argv element or a handle.**
  Not "one that is scrubbed" — none. R8.9 classifies output and names as attacker-controlled byte
  sequences, and there is no reason a Session-lifecycle log record needs any of them.
- **`reason` is the only free-text field**, and its source is fixed: it is the same identifying
  reason that already travels back to the provider in a non-200 hook body (R7.8, R13.7). It is
  composed by this runtime's own exception messages, never from process output, and it is truncated
  to `MAX_FIELD_LENGTH`. Emitting it is therefore no wider a disclosure than the hook response
  already is, and withholding it would leave an operator with a failed Sandbox and no reason.

## Emitting must not be able to fail a lifecycle transition

The design's argument for embedded metric format over `PutMetricData` — "emitting a metric cannot
introduce a synchronous failure into a lifecycle transition" — applies to a log write with the same
force. A `/terminate` that raised because a log sink was unreachable would leave a billable Sandbox
allocated in order to record that it was being deallocated.

So the two halves are separated. `record_for` builds and validates, and raises on a field it may
not emit, because that is a defect in the calling code and is caught by a test rather than met in
production. `emit` writes, and a sink failure is counted and swallowed. `dropped` is readable so
that "the sink is broken" is observable from inside the process rather than being indistinguishable
from "nothing happened".

## The sink is a seam, for the same reason every other transport here is

Reaching CloudWatch Logs needs a client, a region and credentials, none of which exist offline and
none of which this task provisions — the IaC package is phase 12. `LogSink` is therefore one
method, and `StreamLogSink` is the implementation this repository ships: one JSON object per line
on a text stream, which is what a MicroVM's collected stdout already is. That is also what makes
the emitter testable with an `io.StringIO` and no network, which the offline suite requires (R15.9).

A sink is called from inside an async hook and must not block. `StreamLogSink` writes to an
already-open stream; a sink that batched to a remote API would need to do the blocking part on its
own and is why the seam exists rather than a client being named here.
"""

from __future__ import annotations

import enum
import json
import os
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final, Protocol, TextIO, runtime_checkable

__all__ = [
    "EMITTABLE_FIELDS",
    "ENVIRONMENT_VARIABLE",
    "GENERATION_MINIMUM",
    "GENERATION_VARIABLE",
    "LOG_GROUP_PREFIX",
    "LOG_STREAM_SEPARATOR",
    "MAX_FIELD_LENGTH",
    "MAX_LOG_NAME_LENGTH",
    "RESERVED_FIELDS",
    "SESSION_ID_VARIABLE",
    "TENANT_ID_VARIABLE",
    "LogDestination",
    "LogFieldRefused",
    "LogLevel",
    "LogNamingError",
    "LogSink",
    "SessionIdentity",
    "SessionLogEmitter",
    "StreamLogSink",
]

#: One detail value, as a record may carry it. Deliberately narrow: see `_emittable_value` for
#: why `bytes` is refused by name rather than merely being absent from this union.
type FieldValue = str | int | bool | None

#: The log group prefix the design's Observability table fixes. The deployment environment name
#: is the final segment, so one deployment's Sandboxes share a group and two do not.
LOG_GROUP_PREFIX: Final = "/aws/sandbox"

#: The separator between the stream's three segments, and therefore the character none of them
#: may contain. See `_require_segment`.
LOG_STREAM_SEPARATOR: Final = "/"

#: CloudWatch Logs bounds a log group name and a log stream name at 512 characters. Checked here
#: rather than discovered from a `ResourceNotFound` at the first write, because a name that is too
#: long is a Session whose logs went nowhere and whose absence looks like a quiet Sandbox.
MAX_LOG_NAME_LENGTH: Final = 512

#: Characters CloudWatch Logs refuses in a log stream name outright. `*` and `:` are the two the
#: service names; `/` is refused per segment by this module rather than by the service, because a
#: segment carrying one would silently become two.
_FORBIDDEN_STREAM_CHARACTERS: Final = frozenset({"*", ":"})

#: A Session's generation starts at 1 and increments on each continuation, so 0 names no Sandbox
#: that ever existed. The same minimum `control_plane.state.artifacts` applies to the artifact
#: prefix, spelled again here for the reason the module docstring of `runtime.run_config` gives:
#: nothing in `runtime/` imports `control_plane/`.
GENERATION_MINIMUM: Final = 1

#: The environment the provider writes into the MicroVM, naming the four values above. The
#: Sandbox_Runtime cannot derive any of them: they are facts about the Session it was provisioned
#: for, held by the Control_Plane, and they arrive the same way every other deployment value in
#: this repository does.
ENVIRONMENT_VARIABLE: Final = "SANDBOX_ENVIRONMENT"
TENANT_ID_VARIABLE: Final = "SANDBOX_TENANT_ID"
SESSION_ID_VARIABLE: Final = "SANDBOX_SESSION_ID"
GENERATION_VARIABLE: Final = "SANDBOX_GENERATION"

#: The longest a single field value may be once rendered. Applies to `reason`, which is the only
#: field whose length is not bounded by its own shape. A record is a diagnostic, not a transcript.
MAX_FIELD_LENGTH: Final = 1_024

#: Every detail field a record may carry, and no others. Each entry is a decision; see the module
#: docstring for why this is an allow-list and what is deliberately absent from it.
#:
#: - `hook` — which of the four lifecycle hooks this record is about (R7.7).
#: - `phase`, `previousPhase` — `runtime.readiness.RuntimePhase` values, a closed set.
#: - `outcome` — what the transition did: served, refused, failed.
#: - `status` — the HTTP status the hook returned.
#: - `reason` — the identifying reason a non-200 hook already carries (R7.8, R13.7).
#: - `durationMs` — how long the transition took.
#: - `byteCount`, `itemCount` — sizes and counts, of an artifact or a drained queue.
#: - `truncated` — whether a bounded write gave up short (R13.3's truncation marker).
#: - `messageType` — a Sandbox_Protocol message type name, which comes from the catalogue and is
#:   therefore a closed set rather than caller text.
EMITTABLE_FIELDS: Final = frozenset(
    {
        "hook",
        "phase",
        "previousPhase",
        "outcome",
        "status",
        "reason",
        "durationMs",
        "byteCount",
        "itemCount",
        "truncated",
        "messageType",
    }
)

#: The record's own keys, which the emitter produces and a caller may not set. Kept disjoint from
#: `EMITTABLE_FIELDS` by an assertion in the suite: a detail field named `sessionId` could
#: otherwise overwrite the identity the whole record exists to carry.
_TIMESTAMP: Final = "timestamp"
_LEVEL: Final = "level"
_EVENT: Final = "event"
_TENANT_ID: Final = "tenantId"
_SESSION_ID: Final = "sessionId"
_GENERATION: Final = "generation"
_INSTANCE_ID: Final = "instanceId"

RESERVED_FIELDS: Final = frozenset(
    {
        _TIMESTAMP,
        _LEVEL,
        _EVENT,
        _TENANT_ID,
        _SESSION_ID,
        _GENERATION,
        _INSTANCE_ID,
    }
)

#: An event name is chosen by the runtime, never by data, so its shape is checked rather than its
#: membership of a closed set: the later observability tasks add events, and a closed set here
#: would make every one of them an edit to this module. Lowercase, dots and underscores, so that
#: `hook.run` and `hook.terminate` sort together and no event name needs escaping to be read.
_EVENT_CHARACTERS: Final = frozenset("abcdefghijklmnopqrstuvwxyz0123456789._")


class LogNamingError(ValueError):
    """A value cannot become part of a log group or log stream name that identifies the Session."""


class LogFieldRefused(ValueError):
    """A record was asked to carry a field this runtime does not emit.

    A defect in the calling code rather than an operational condition: the fields a lifecycle
    record may carry are enumerated in `EMITTABLE_FIELDS`, so a name outside it means the caller
    intended to log something the boundary does not admit. Raised by `record_for` and therefore
    met in a test rather than in a hook — see the module docstring on why `emit` does not raise.
    """


class LogLevel(enum.StrEnum):
    """The severity of one record. Three values, because a fourth would not change any decision."""

    #: The ordinary case: a transition happened.
    INFO = "INFO"
    #: Something was refused or gave up short, and the Session continues.
    WARNING = "WARNING"
    #: A transition did not complete.
    ERROR = "ERROR"


def _require_segment(name: str, value: str) -> str:
    """Reject a value that would change the shape or the reach of a log name.

    The `/` rejection is the load-bearing one, and it is the same argument
    `control_plane.state.artifacts.tenant_artifact_prefix` makes about an S3 prefix. A Tenant
    identifier of `acme/eu` with Session `s1` produces the stream `acme/eu/s1/1`, which is
    indistinguishable from Tenant `acme`, Session `eu` at generation... nothing, because the
    generation segment has moved. Two Sessions would share a stream name, or an operator following
    R14.3's procedure would construct a name that resolves to another Tenant's stream. Neither is
    recoverable after the fact, so the value is refused before a name is built from it.
    """
    if not value:
        raise LogNamingError(f"{name} must not be empty")
    if LOG_STREAM_SEPARATOR in value:
        raise LogNamingError(
            f"{name} must not contain {LOG_STREAM_SEPARATOR!r}, which would add a segment to "
            f"the log stream name and make it name a different Session: {value!r}"
        )
    for character in sorted(_FORBIDDEN_STREAM_CHARACTERS):
        if character in value:
            raise LogNamingError(
                f"{name} must not contain {character!r}, which CloudWatch Logs refuses in a "
                f"log stream name: {value!r}"
            )
    if any(not character.isprintable() or character.isspace() for character in value):
        raise LogNamingError(
            f"{name} must be printable and contain no whitespace: {value!r}"
        )
    return value


def _require_generation(generation: int) -> int:
    if isinstance(generation, bool) or not isinstance(generation, int):
        raise LogNamingError(f"generation must be an integer: {generation!r}")
    if generation < GENERATION_MINIMUM:
        raise LogNamingError(
            f"generation must be at least {GENERATION_MINIMUM}: {generation}"
        )
    return generation


@dataclass(frozen=True, slots=True)
class SessionIdentity:
    """The Session one Sandbox_Runtime process is serving, as the log names spell it.

    Frozen, because a runtime serves one Session for one generation: an identity that could be
    reassigned would let a record land in a stream naming a Session that did not produce it.

    None of the four values is derivable inside the MicroVM. They are provisioning facts the
    provider carries in, which is why `from_environment` exists and why there is no default for
    any of them — a runtime that was told nothing has no Session to identify, and inventing a
    placeholder would produce a stream name that looks like a Session's and is not.
    """

    environment: str
    tenant_id: str
    session_id: str
    generation: int

    def __post_init__(self) -> None:
        _require_segment("environment", self.environment)
        _require_segment("tenant_id", self.tenant_id)
        _require_segment("session_id", self.session_id)
        _require_generation(self.generation)

    @classmethod
    def from_environment(
        cls, environment: Mapping[str, str] | None = None
    ) -> SessionIdentity:
        """Read the identity the provider wrote into this MicroVM's environment.

        The mapping is a parameter so the offline suite can state a provisioning without one, not
        so a caller may supply one at runtime: the default is the process environment, which the
        Session's own code cannot reach before `/run`.

        Raises:
            LogNamingError: a value is absent, or is not one a log name can be built from.
        """
        source = os.environ if environment is None else environment
        missing = [
            name
            for name in (
                ENVIRONMENT_VARIABLE,
                TENANT_ID_VARIABLE,
                SESSION_ID_VARIABLE,
                GENERATION_VARIABLE,
            )
            if not source.get(name)
        ]
        if missing:
            raise LogNamingError(
                f"the Sandbox environment is missing {', '.join(missing)}, so no log group and "
                f"stream identifying the Session can be named (R14.1)"
            )
        raw_generation = source[GENERATION_VARIABLE]
        try:
            generation = int(raw_generation)
        except ValueError as exc:
            raise LogNamingError(
                f"{GENERATION_VARIABLE} is not an integer: {raw_generation!r}"
            ) from exc
        return cls(
            environment=source[ENVIRONMENT_VARIABLE],
            tenant_id=source[TENANT_ID_VARIABLE],
            session_id=source[SESSION_ID_VARIABLE],
            generation=generation,
        )


@dataclass(frozen=True, slots=True)
class LogDestination:
    """The log group and stream one Sandbox's records are written under (R14.1).

    Built only by `of`, so that the two names have one producer. Held as a pair rather than
    recomposed at each write, because the stream name is the identity half of R14.1 and a name
    rebuilt per record is a name that can differ per record.
    """

    log_group: str
    log_stream: str

    @classmethod
    def of(cls, identity: SessionIdentity) -> LogDestination:
        """`/aws/sandbox/<env>` and `<tenantId>/<sessionId>/<generation>`.

        The design's Observability table, verbatim, and the only place either string is composed.

        Raises:
            LogNamingError: either name exceeds what CloudWatch Logs accepts.
        """
        log_group = f"{LOG_GROUP_PREFIX}{LOG_STREAM_SEPARATOR}{identity.environment}"
        log_stream = LOG_STREAM_SEPARATOR.join(
            (identity.tenant_id, identity.session_id, str(identity.generation))
        )
        return cls(
            log_group=_require_length("log group name", log_group),
            log_stream=_require_length("log stream name", log_stream),
        )


def _require_length(name: str, value: str) -> str:
    if len(value) > MAX_LOG_NAME_LENGTH:
        raise LogNamingError(
            f"the {name} is {len(value)} characters, which exceeds the "
            f"{MAX_LOG_NAME_LENGTH} CloudWatch Logs accepts: {value!r}"
        )
    return value


@runtime_checkable
class LogSink(Protocol):
    """Writes one rendered record to the destination the emitter named.

    One method, because that is the entire dependency: the runtime decides the two names and the
    record, and the deployment holds the transport. The destination travels with each write rather
    than being bound at construction, so a sink stays stateless and the naming stays in one place.

    An implementation must not block and must not raise into its caller's business — `emit` guards
    against the second, and there is nothing it can do about the first.
    """

    def write(self, destination: LogDestination, record: str) -> None:
        """Write `record`, a single rendered JSON object, under `destination`."""
        ...


class StreamLogSink:
    """Writes one JSON object per line to a text stream, `sys.stdout` by default.

    This is what a MicroVM's collected output already is, so it is the sink a deployed Sandbox
    uses: the platform routes the stream to the configured log group, and the group and stream
    names travel in the record as well as being the destination, so a record remains attributable
    if it is ever read from somewhere other than the stream it was written to.

    It is also the sink the offline suite uses, with an `io.StringIO` and no network.
    """

    def __init__(self, stream: TextIO | None = None) -> None:
        """Bind the stream. None means `sys.stdout`, read at write time rather than captured.

        Read at write time because a test, and `contextlib.redirect_stdout`, replace
        `sys.stdout` after this object is built; a captured reference would write past the
        replacement to a stream nobody is reading.
        """
        self._stream = stream

    def write(self, destination: LogDestination, record: str) -> None:
        """Write one line, flushed.

        Flushed because the process this runs in is killed by its provider rather than shut down:
        a buffered record describing a `/terminate` would be lost at exactly the moment it is the
        only account of what happened.
        """
        stream = sys.stdout if self._stream is None else self._stream
        stream.write(f"{record}\n")
        stream.flush()


class SessionLogEmitter:
    """Emits Session-identifying structured records for one Sandbox_Runtime process (R14.1).

    One per process, holding the identity, the destination and the sink. The instance identifier
    is bound separately by `bind_instance` because it does not exist yet when this is built: it is
    generated inside `/run` (R7.12), and records emitted before that carry no `instanceId` rather
    than a placeholder for one.
    """

    def __init__(
        self,
        *,
        identity: SessionIdentity,
        sink: LogSink | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        """Bind the identity and the sink, and derive the destination once.

        `sink` defaults to `StreamLogSink()`, which is the deployed configuration as well as the
        testable one, so there is no arrangement in which this emitter silently discards records.

        `clock` returns the moment a record is stamped with; the default is UTC now. It is
        injectable so that a record's rendered shape is assertable without freezing time.
        """
        self._identity = identity
        self._destination = LogDestination.of(identity)
        self._sink = StreamLogSink() if sink is None else sink
        self._clock = _utc_now if clock is None else clock
        self._instance_id: str | None = None
        self._dropped = 0

    @property
    def identity(self) -> SessionIdentity:
        """The Session this emitter's records name."""
        return self._identity

    @property
    def destination(self) -> LogDestination:
        """The log group and stream every record is written under (R14.1)."""
        return self._destination

    @property
    def instance_id(self) -> str | None:
        """The bound Runtime instance identifier, or None before `/run` generated one."""
        return self._instance_id

    @property
    def dropped(self) -> int:
        """Records the sink refused. Non-zero means the log transport is broken, not the Session."""
        return self._dropped

    def bind_instance(self, instance_id: str) -> None:
        """Carry this runtime process's instance identifier on every subsequent record (R7.12).

        Called once, from `/run`, with `runtime.session_values.SessionValues.instance_id`. Binding
        it twice is refused: the identifier distinguishes writers within one stream, and a writer
        that changed its own identity mid-stream would make that distinction useless.

        Raises:
            LogNamingError: the identifier is not one a record can carry, or one is already bound.
        """
        if self._instance_id is not None:
            raise LogNamingError(
                "this emitter already carries an instance identifier; a runtime process has one "
                "for its whole life, generated once during /run (R7.12)"
            )
        self._instance_id = _require_segment("instance_id", instance_id)

    def record_for(
        self,
        event: str,
        *,
        level: LogLevel = LogLevel.INFO,
        detail: Mapping[str, FieldValue] | None = None,
    ) -> str:
        """Build and validate one record, rendered as a single-line JSON object.

        Separate from `emit` so that what a record contains is assertable without a sink, and so
        that the validation failure a defect produces is raised rather than swallowed. `emit`
        swallows sink failures and this raises caller failures; the two are not the same kind of
        thing and must not have the same outcome.

        Raises:
            LogFieldRefused: a detail field is not one this runtime emits.
            LogNamingError: the event name is not one a record can carry.
        """
        payload: dict[str, FieldValue] = {
            _TIMESTAMP: self._timestamp(),
            _LEVEL: level.value,
            _EVENT: _require_event(event),
            _TENANT_ID: self._identity.tenant_id,
            _SESSION_ID: self._identity.session_id,
            _GENERATION: self._identity.generation,
        }
        if self._instance_id is not None:
            payload[_INSTANCE_ID] = self._instance_id
        for field, value in (detail or {}).items():
            if field not in EMITTABLE_FIELDS:
                raise LogFieldRefused(
                    f"{field!r} is not a field the Sandbox_Runtime emits; the fields a lifecycle "
                    f"record may carry are {sorted(EMITTABLE_FIELDS)}, and a name outside that "
                    f"set is refused rather than dropped so that nothing is logged by accident"
                )
            payload[field] = _emittable_value(field, value)
        # `ensure_ascii` so that one record is one line of ASCII whatever an identifier contains,
        # and separators without spaces because a log line is read by machines far more often than
        # by people. Sorting is deliberately *not* applied: the identity fields lead every record,
        # which is what makes a raw stream readable.
        return json.dumps(payload, ensure_ascii=True, separators=(",", ":"))

    def emit(
        self,
        event: str,
        *,
        level: LogLevel = LogLevel.INFO,
        detail: Mapping[str, FieldValue] | None = None,
    ) -> None:
        """Write one record, and never fail the caller because the sink did.

        The design's reason for choosing embedded metric format over `PutMetricData` — emitting a
        signal must not add a synchronous failure to a lifecycle transition — applies here without
        change. A `/terminate` that raised because a log sink was unreachable would hold a billable
        Sandbox allocated in order to record that it was being released. So a sink failure
        increments `dropped` and returns.

        A `LogFieldRefused` from `record_for` is *not* caught. It is a defect in this repository's
        own code, it is raised before anything is written, and the suite is where it is met.
        """
        record = self.record_for(event, level=level, detail=detail)
        try:
            self._sink.write(self._destination, record)
        except Exception:  # noqa: BLE001 - a broken log sink must not fail a lifecycle transition
            self._dropped += 1

    def _timestamp(self) -> str:
        """RFC 3339 in UTC, to microseconds.

        Rendered by this module rather than left to the sink, so that two sinks cannot disagree
        about when a record happened, and so that the timestamp survives a transport that does not
        add one of its own.

        A naive `datetime` is read as UTC rather than refused. The clock is injected by this
        repository's own code and a test clock returning naive moments is an ordinary thing to
        write; interpreting one as local time would be the surprising reading, and refusing it
        would put a raise on the emission path for no operational reason.
        """
        moment = self._clock()
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=UTC)
        return moment.astimezone(UTC).isoformat()


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _require_event(event: str) -> str:
    """Reject an event name that is not the closed vocabulary's shape."""
    if not event:
        raise LogNamingError("an event name must not be empty")
    if not set(event) <= _EVENT_CHARACTERS:
        raise LogNamingError(
            f"an event name is lowercase letters, digits, {'.'!r} and {'_'!r}: {event!r}"
        )
    return event


def _emittable_value(field: str, value: FieldValue) -> FieldValue:
    """Bound and type-check one detail value.

    `bytes` is refused explicitly rather than falling through the type check, because it is the
    shape every attacker-controlled value in this runtime has: `runtime.filesystem` and
    `runtime.process` are byte-typed throughout (R8.9). A caller holding bytes and wanting them in
    a log record is a caller about to emit process output or a filesystem path, and the answer to
    that is no rather than a decoding.
    """
    if isinstance(value, bytes | bytearray | memoryview):
        raise LogFieldRefused(
            f"{field!r} was given bytes; the Sandbox_Runtime does not emit byte values, which "
            f"are how process output, file content and filesystem paths are spelled here (R8.9)"
        )
    if value is None or isinstance(value, bool | int):
        return value
    if isinstance(value, str):
        if len(value) <= MAX_FIELD_LENGTH:
            return value
        # Truncated with a marker rather than refused: `reason` is the field this applies to, and
        # a long reason is an operational fact about a failure, not a defect in the caller. The
        # marker is there so a truncated reason is not read as a complete one.
        return f"{value[:MAX_FIELD_LENGTH]}...[truncated]"
    raise LogFieldRefused(
        f"{field!r} must be a string, an integer, a boolean or null, "
        f"not {type(value).__name__}"
    )
