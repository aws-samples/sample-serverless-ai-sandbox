# kiro-classification: public
"""Property 9: readiness gating, and configuration path equivalence (R7.8, R7.11).

The design states one property with two conjuncts, and they are about different things. The first
is a *prohibition* — nothing is served and nothing is configured until `/run` has returned 200 —
and the second is an *equality* — the same document applies the same configuration whichever way
the provider delivered it. Both are asserted here over one drawn domain of configuration
documents, because both are claims about "for all per-Session configurations" and drawing the
document once and driving it through both halves is what makes them claims about the same input.

## Readiness gating: quantified over the request's timing, not only over the configuration

R7.8's first sentence is about an *ordering*, so a test that only fired a request before `/run`
would be checking one point on a timeline that has three interesting ones. Every drawn document is
therefore probed at four moments, and the probe is the same pair of requests each time:

1. **Before `/run`.** Over the real HTTP transport, so the mapping onto a status code is the
   deployed one rather than a handler return value.
2. **Inside `/run`, before the configuration is read.** `LifecycleActions` is a Protocol, so the
   real `SandboxLifecycle` is wrapped in `_Probing`, which issues the probe and delegates. The
   probe runs on the application's own event loop while the gate is `STARTING`, which is a request
   arriving mid-hook at a real suspension point rather than a phase set up by hand.
3. **Inside `/run`, after the configuration has been applied and before 200 is returned.** This is
   the moment the prohibition is easiest to break by accident: everything is configured and the
   only thing still holding the handler closed is that `runtime.hooks` has not called
   `finish_start` yet. A runtime that opened the gate as the last act of applying configuration
   would pass every other assertion here.
4. **After `/run` has answered.** Not a refusal but its complement, and it is what keeps the three
   refusals from being vacuous — see the non-vacuity note below.

The probe pair is one well-formed `port.expose` and one frame that is not a decodable message.
Both matter. `runtime.protocol_handler` admits before it decodes, deliberately, so that a closed
runtime does no work on attacker-supplied bytes; the malformed frame is how that ordering is
observable from outside. Before readiness it draws the readiness refusal, and after readiness the
same bytes draw a decode error, and the difference between those two answers is the whole of the
claim.

R7.8's second sentence — before `/run`, no per-Session configuration is applied — is asserted
directly rather than inferred. `SandboxLifecycle` exposes `configuration` and `values` and
`ExposedPorts` exposes `declared`, so the *absence* is readable, which is the point 8.5 made of
exposing them.

## Configuration path equivalence: the same bytes, two providers

The equality is stated over "the applied configuration", so it is asserted four ways over the same
document: the `RunConfiguration` each Sandbox holds, the port set each published, the URL
`port.expose` answers with for every declared port — the applied configuration observed from
outside, over the protocol, which is the only view a caller has — and the filesystem tree a
`restore` section produced.

The two Sandboxes differ only in delivery. The inline one is given the document as its payload; the
by-reference one is given `{"startConfigRef": ...}` and fetches the document from a recording
State_Store. Above the payload limit the inline path cannot be exercised at the anchored 16 KB
ceiling — refusing an oversized payload is what that ceiling is for — so the inline Sandbox is
built with `max_payload_bytes` large enough to carry the document it is given. That is not a
weakening. `max_run_config_bytes` is *the provider's* declaration and the providers do not agree on
it: the Lambda MicroVM provider declares 16,384 and the Fargate task provider declares 8,192. A
10 KB document is therefore inline on one deployment and reference-only on the other, and R7.11's
claim is precisely that those two deployments apply the same configuration. The anchored limit is
asserted separately, on the reader alone, where it belongs: an above-limit document is refused
inline and an at-limit document is not.

## Documents that fail to apply are in the domain

A malformed document is not outside "for all per-Session configurations": R7.8's prohibition has to
hold on the failure path too, and it is the failure path where a partially applied configuration
would be invisible. So roughly half the drawn documents are defective, across sixteen named
defects that fail at four different depths — the payload is not a JSON object, a field is not
readable, the document is readable but names state the State_Store does not hold, and the document
is readable and the restore succeeds but publishing it fails. The last is the interesting one: the
restored files are on disk, the gate is `FAILED`, and no configuration is applied.

Failing documents are compared across the two delivery paths as well, and for most defects the
*reason* is compared too, not merely the status. That is the sharpest form of "there is no second
parser": both paths hand the same bytes to `parse_configuration`, so they must produce the same
sentence. The four defects excluded from that comparison are the ones that fail before the
document is reached, where the two paths are genuinely describing different things — an inline
payload that is not a JSON object is refused as "the run hook payload", and the same bytes fetched
from the State_Store are refused as "the per-Session configuration". The difference is the noun,
and the noun is correct in each case.

## Non-vacuity

Every refusal assertion has its complement asserted in the same example, which is the cheapest and
most reliable form of this: `assert_the_gate_is_checked_before_the_body_is_decoded` requires the
same malformed frame that drew `503` before `/run` to draw `400` with a decoded `error.decode`
afterwards, so "503 for everything" fails the property. Likewise `assert_the_run_hook_matched_the_document`
requires an applicable document to reach `SERVING` and expose its ports, so "nothing ever serves"
fails too.

Beyond that, the three defective runtimes the property is meant to catch are built and run against
the property's own assertion functions:

* `_SecondParserLifecycle` fetches the document through the real reader and then parses it with a
  parser of its own — one that does not normalise the port set and ignores fields it does not know.
  Placed on the by-reference side it is a second parser; placed on the inline side it is an inline
  shortcut that accepts a document the other path refuses. Both are demonstrated.
* `_EagerlyOpeningLifecycle` opens the gate before applying the configuration, which is the one
  arrangement the third probe moment exists to catch.
* `_PreconfiguredLifecycle` applies a configuration when it is constructed rather than when `/run`
  runs, which is R7.8's second sentence violated.

Each is asserted to *fail* the same function the property calls. None is an analogy: all three are
real `LifecycleActions` wired into the real application behind the real gate.

## Budget, and why the defect axis is parametrised rather than drawn

The document shape — applicable, or one of seventeen named defects — is a `parametrize` axis, and
each of the eighteen cases runs the design's floor of 100 examples over the axes that stay drawn:
the size band, the port set, and which optional fields the document carries. So the property runs
1,800 examples in total.

Drawing the defect was the first shape of this and it under-covered badly. Measured over 200 draws,
four of the seventeen defects never appeared and one appeared 24 times: `sampled_from` inside a
composite reuses interesting prefixes rather than sampling uniformly, so a seventeen-way choice
does not come out seventeen ways. The defect axis is the one axis where coverage is both cheap to
guarantee and load-bearing — each member is a distinct refusal reached by a distinct path through
the parser, the restorer or the publish step — so it is enumerated. The axes that remain drawn are
the open-ended ones, where enumeration is not available and a random walk is the right instrument.

Cost is two Sandboxes per example, each built and driven through the whole ASGI application, which
measures 6.2 ms: about 2 ms to construct the application, 1.3 ms for the client's event loop, and
eight protocol requests at 0.38 ms each. That is 12.5 ms per example and about 22 seconds for the
property, against a per-test budget of 300 seconds. The State_Store is faked and never reached: the
offline suite denies outbound network access, and `runtime.run_config` declares the fetch as one
method precisely so that a recording stand-in is the whole of what a test needs.
"""

from __future__ import annotations

import asyncio
import enum
import hashlib
import io
import json
import tarfile
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from http import HTTPStatus
from pathlib import Path
from typing import Final

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from starlette.testclient import TestClient

from protocol.codec.messages import decode, encode
from protocol.schema import (
    ENVELOPE_KEY_BODY,
    ENVELOPE_KEY_ID,
    ENVELOPE_KEY_TYPE,
    ENVELOPE_KEY_VERSION,
    load_catalogue,
)
from runtime.app import CBOR_MEDIA_TYPE, HOOK_PATH_PREFIX, PROTOCOL_PATH, create_app
from runtime.filesystem import ConfinedRoot
from runtime.lifecycle import SandboxLifecycle
from runtime.operations import OperationRegistry
from runtime.ports import PORT_EXPOSE, ExposedPorts
from runtime.protocol_handler import SandboxProtocolHandler
from runtime.readiness import ReadinessGate, RuntimePhase
from runtime.run_config import (
    CONFIG_REFERENCE_KEY,
    MAX_PERSIST_DEADLINE_MS,
    MAX_RUN_CONFIG_BYTES,
    ConfigurationError,
    ReferenceNotFound,
    RunConfiguration,
    RunConfigurationReader,
    parse_configuration,
)
from runtime.session_values import SessionValues
from tests.harness import MINIMUM_EXAMPLES

CATALOGUE: Final = load_catalogue()

#: The three State_Store references this module uses. Distinct constants rather than drawn
#: strings: a reference is opaque to the runtime, so varying it varies nothing this property is
#: about, and three fixed ones make "which reference was read" an assertion rather than a lookup.
CONFIG_REFERENCE: Final = "tenants/tnt-9/sessions/ses-9/start-config.json"
RESTORE_REFERENCE: Final = "tenants/tnt-9/sessions/ses-9/0/state.tar"
PERSIST_REFERENCE: Final = "tenants/tnt-9/sessions/ses-9/1/state.tar"

#: The port range drawn documents declare, and one port outside it. `port.expose` is asked about
#: the undeclared port on every Sandbox, because the refusal it produces is also part of the
#: applied configuration observed from outside: it is what the declared set decided.
_MIN_PORT: Final = 1
_MAX_DRAWN_PORT: Final = 60_000
UNDECLARED_PORT: Final = 65_535

#: The alphabet a drawn endpoint hostname and a drawn persist path component are built from. No
#: dot and no separator, so a drawn path is unambiguously relative and carries no `..` component;
#: what those names do is `runtime.persist`'s subject rather than this property's.
_NAME_ALPHABET: Final = "abcdefghijklmnopqrstuvwxyz0123456789-_"

#: How far above the payload limit an above-limit document is padded.
_MAX_OVERSHOOT: Final = 4_096

#: The tree a `restore` section restores. Fixed, and named in ASCII: this property compares two
#: restored trees for equality rather than asserting anything about what a name may contain, and
#: Property 7 owns the round trip. ASCII also keeps the comparison off the filesystem's opinion of
#: unusual names, which task 8.4 found is a thing to probe rather than predict.
RESTORED_TREE: Final[Mapping[str, bytes]] = {
    "restored/notes.txt": b"a line\n",
    "restored/nested/data.bin": bytes(range(64)),
}


def _archive(entries: Mapping[str, bytes]) -> bytes:
    """A `tar` stream carrying regular files at the given relative paths."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as stream:
        for name, content in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mode = 0o644
            stream.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


ARCHIVE: Final = _archive(RESTORED_TREE)
ARCHIVE_DIGEST: Final = hashlib.sha256(ARCHIVE).hexdigest()


class Delivery(enum.StrEnum):
    """The two ways R7.11 admits for one configuration document to reach the `/run` hook."""

    INLINE = "delivered inline"
    BY_REFERENCE = "fetched from the State_Store by reference"


class Band(enum.StrEnum):
    """Where a document's serialised size sits relative to the provider-declared limit."""

    BELOW = "below the payload limit"
    AT = "exactly at the payload limit"
    ABOVE = "above the payload limit"


class Defect(enum.StrEnum):
    """The ways a drawn document fails to apply, each producing a distinct refusal.

    Ordered by the depth at which the failure happens: the payload is not an object at all, then a
    field the parser reads is not one, then the document is readable but names state that cannot be
    restored, then the document is readable and the restore succeeds and publishing it fails.
    """

    EMPTY_PAYLOAD = "an empty payload"
    NOT_JSON = "a payload that is not JSON"
    NOT_UTF8 = "a payload that is not UTF-8"
    NOT_AN_OBJECT = "a JSON array rather than an object"

    UNKNOWN_KEY = "a key this runtime does not understand"
    PORT_OUT_OF_RANGE = "an out-of-range port"
    PORT_NOT_A_NUMBER = "a declared port that is not a number"
    TEMPLATE_EMPTY = "an empty endpoint URL template"
    RESTORE_WITHOUT_REFERENCE = "a restore section naming nothing"
    RESTORE_DIGEST_MALFORMED = "a restore digest that is not a digest"
    PERSIST_ABSOLUTE_PATH = "a persist path that is absolute"
    PERSIST_DEADLINE_TOO_LONG = "a persist deadline beyond this runtime's ceiling"

    RESTORE_REFERENCE_ABSENT = "a restore reference the State_Store does not hold"
    RESTORE_ARCHIVE_UNREADABLE = (
        "a restore reference holding bytes that are not an archive"
    )
    RESTORE_DIGEST_MISMATCH = "a restore digest the archive does not match"

    PORTS_WITHOUT_TEMPLATE = "declared ports with no endpoint URL template"
    TEMPLATE_WITHOUT_PLACEHOLDER = (
        "an endpoint template that addresses every port alike"
    )


#: The four defects that are not JSON objects, and therefore fail before the configuration
#: document is reached. Their refusals name the payload rather than the configuration, which is why
#: the reason comparison excludes them. See the module docstring.
_BEFORE_THE_DOCUMENT: Final = frozenset(
    {
        Defect.EMPTY_PAYLOAD,
        Defect.NOT_JSON,
        Defect.NOT_UTF8,
        Defect.NOT_AN_OBJECT,
    }
)

_RAW_PAYLOADS: Final[Mapping[Defect, bytes]] = {
    Defect.EMPTY_PAYLOAD: b"",
    Defect.NOT_JSON: b"this is not a configuration document",
    Defect.NOT_UTF8: b"\xff\xfe\xfd",
    Defect.NOT_AN_OBJECT: b"[]",
}


# --- The drawn case ------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Drawn:
    """One configuration document, and what this module knows about it before driving it."""

    document: bytes
    band: Band
    defect: Defect | None
    #: What the State_Store holds besides the configuration document itself.
    stored: Mapping[str, bytes]
    #: Whether `/run` should return 200 for this document.
    applies: bool

    @property
    def is_json_object(self) -> bool:
        """Whether the payload has a shape `reference_in` can read a delivery decision off."""
        return self.defect not in _BEFORE_THE_DOCUMENT

    @property
    def describe(self) -> str:
        detail = "applicable" if self.defect is None else str(self.defect)
        return f"a {len(self.document)}-byte document, {self.band}, {detail}"


def _sized(document: bytes, target: int | None) -> bytes:
    """Pad `document` to exactly `target` bytes without changing what it means.

    The padding is JSON whitespace inserted after the opening brace, which is the one padding
    vehicle that is orthogonal to every field and every defect: it changes no key, no value and no
    malformedness, so a document at the payload limit and the same document below it are the same
    logical input. A payload that is not JSON is padded by appending spaces, which leaves it just
    as undecodable.
    """
    if target is None:
        return document
    extra = target - len(document)
    assert extra >= 0, (
        f"a {len(document)}-byte document cannot be padded down to {target}; the drawn field "
        f"shapes are meant to stay well under the payload limit"
    )
    if document[:1] in (b"{", b"["):
        return document[:1] + b" " * extra + document[1:]
    return document + b" " * extra


def _restore_section(draw: st.DrawFn) -> dict[str, object]:
    """A `restore` section naming the fixed archive, optionally with what the writer recorded."""
    section: dict[str, object] = {"reference": RESTORE_REFERENCE}
    if draw(st.booleans()):
        section["sizeBytes"] = len(ARCHIVE)
    if draw(st.booleans()):
        section["sha256"] = ARCHIVE_DIGEST
    return section


def _persist_section(draw: st.DrawFn) -> dict[str, object]:
    """A `persist` section, the half of the document task 8.8 added.

    Drawn even though `/run` does not act on it: equivalence has to hold for every field the
    document can carry, and a field only one delivery path could express would be the failure this
    property is looking for.
    """
    section: dict[str, object] = {"reference": PERSIST_REFERENCE}
    paths = draw(
        st.lists(
            st.lists(
                st.text(alphabet=_NAME_ALPHABET, min_size=1, max_size=8),
                min_size=1,
                max_size=3,
            ).map("/".join),
            max_size=3,
        )
    )
    if paths:
        # Drawn as a list rather than a set, so duplicated and unordered path sets occur. The
        # parser normalises both, which is part of what the two paths have to agree on.
        section["paths"] = paths
    if draw(st.booleans()):
        section["deadlineMs"] = draw(
            st.integers(min_value=1, max_value=MAX_PERSIST_DEADLINE_MS)
        )
    if draw(st.booleans()):
        section["compress"] = draw(st.booleans())
    return section


def _template(host: str) -> str:
    return f"https://{host}.endpoint.example/ports/{{port}}"


@st.composite
def run_config(draw: st.DrawFn, defect: Defect | None) -> Drawn:
    """Draw one configuration document with the given defect, or none, at a drawn size band.

    The defect is a parameter rather than a draw. Drawing it was the first shape of this generator
    and it under-covered badly: over 200 examples four of the seventeen defects were never drawn at
    all, because `sampled_from` reuses interesting prefixes rather than sampling uniformly. The
    defect axis is small, enumerable and exactly the axis whose coverage matters — each member is a
    distinct refusal on a distinct code path — so the property is parametrised over it and every
    member gets the design's full iteration floor. What stays drawn is what is genuinely
    open-ended: the size band, the port set, and which optional fields the document carries.
    """
    # An empty payload is the one document with no size to speak of, so it occurs only below the
    # limit; padding it would turn it into a different defect.
    bands = (Band.BELOW,) if defect is Defect.EMPTY_PAYLOAD else tuple(Band)
    band = draw(st.sampled_from(bands))
    target = {
        Band.BELOW: None,
        Band.AT: MAX_RUN_CONFIG_BYTES,
        Band.ABOVE: MAX_RUN_CONFIG_BYTES
        + draw(st.integers(min_value=1, max_value=_MAX_OVERSHOOT)),
    }[band]

    if defect is not None and defect in _RAW_PAYLOADS:
        return Drawn(
            document=_sized(_RAW_PAYLOADS[defect], target),
            band=band,
            defect=defect,
            stored={},
            applies=False,
        )

    ports = draw(
        st.lists(
            st.integers(min_value=_MIN_PORT, max_value=_MAX_DRAWN_PORT), max_size=4
        )
    )
    host = draw(st.text(alphabet=_NAME_ALPHABET, min_size=1, max_size=12))
    # Drawn unconditionally, so that the draw sequence does not depend on the port set. A template
    # with no declared ports is an applicable configuration: it says how a port would be addressed
    # on this endpoint and declares none.
    template_only = draw(st.booleans())
    body: dict[str, object] = {}
    if ports:
        # A list rather than a sorted set: the parser sorts and de-duplicates, and a document that
        # differs from another only in port order must apply the same configuration.
        body["exposedPorts"] = ports
    if ports or template_only:
        body["endpointUrlTemplate"] = _template(host)
    stored: dict[str, bytes] = {}
    if draw(st.booleans()):
        body["restore"] = _restore_section(draw)
        stored[RESTORE_REFERENCE] = ARCHIVE
    if draw(st.booleans()):
        body["persist"] = _persist_section(draw)

    if defect is not None:
        _spoil(body, stored, defect, host=host)

    return Drawn(
        document=_sized(json.dumps(body).encode(), target),
        band=band,
        defect=defect,
        stored=stored,
        applies=defect is None,
    )


def _spoil(
    body: dict[str, object],
    stored: dict[str, bytes],
    defect: Defect,
    *,
    host: str,
) -> None:
    """Introduce exactly one defect into an otherwise applicable document."""
    if defect is Defect.UNKNOWN_KEY:
        # A misspelling rather than an invented key, because a misspelled key is the failure the
        # parser refuses unknown keys to catch: it would otherwise apply less than was asked for.
        body["exposedPort"] = [8080]
    elif defect is Defect.PORT_OUT_OF_RANGE:
        body["exposedPorts"] = [0]
        body["endpointUrlTemplate"] = _template(host)
    elif defect is Defect.PORT_NOT_A_NUMBER:
        body["exposedPorts"] = ["8080"]
        body["endpointUrlTemplate"] = _template(host)
    elif defect is Defect.TEMPLATE_EMPTY:
        body["endpointUrlTemplate"] = ""
    elif defect is Defect.RESTORE_WITHOUT_REFERENCE:
        body["restore"] = {}
    elif defect is Defect.RESTORE_DIGEST_MALFORMED:
        body["restore"] = {"reference": RESTORE_REFERENCE, "sha256": "abc"}
    elif defect is Defect.PERSIST_ABSOLUTE_PATH:
        body["persist"] = {"reference": PERSIST_REFERENCE, "paths": ["/etc/passwd"]}
    elif defect is Defect.PERSIST_DEADLINE_TOO_LONG:
        body["persist"] = {
            "reference": PERSIST_REFERENCE,
            "deadlineMs": MAX_PERSIST_DEADLINE_MS + 1,
        }
    elif defect is Defect.RESTORE_REFERENCE_ABSENT:
        body["restore"] = {"reference": RESTORE_REFERENCE}
        stored.pop(RESTORE_REFERENCE, None)
    elif defect is Defect.RESTORE_ARCHIVE_UNREADABLE:
        body["restore"] = {"reference": RESTORE_REFERENCE}
        stored[RESTORE_REFERENCE] = b"not an archive at all"
    elif defect is Defect.RESTORE_DIGEST_MISMATCH:
        body["restore"] = {"reference": RESTORE_REFERENCE, "sha256": "0" * 64}
        stored[RESTORE_REFERENCE] = ARCHIVE
    elif defect is Defect.PORTS_WITHOUT_TEMPLATE:
        body["exposedPorts"] = [8080]
        body.pop("endpointUrlTemplate", None)
    elif defect is Defect.TEMPLATE_WITHOUT_PLACEHOLDER:
        body["endpointUrlTemplate"] = f"https://{host}.endpoint.example/every-port"
    else:  # pragma: no cover - every defect is handled above
        raise AssertionError(f"no document shape is defined for {defect}")


# --- The protocol requests the probe uses --------------------------------------------------


def expose_wire(port: int) -> bytes:
    """An encoded `port.expose` request for `port`."""
    return encode(
        {
            ENVELOPE_KEY_VERSION: CATALOGUE.protocol_version,
            ENVELOPE_KEY_TYPE: PORT_EXPOSE,
            ENVELOPE_KEY_ID: b"property-9",
            ENVELOPE_KEY_BODY: {
                CATALOGUE.messages[PORT_EXPOSE].field_by_name("port").key: port
            },
        },
        catalogue=CATALOGUE,
    )


#: A frame that is a CBOR item and not a Sandbox_Protocol message. Sent alongside the well-formed
#: one at every probe moment, because `runtime.protocol_handler` admits before it decodes and this
#: is the request that makes that ordering observable: before readiness it draws the readiness
#: refusal, and afterwards the same bytes draw a decode error.
MALFORMED_FRAME: Final = b"\x00"

_PROBES: Final[tuple[tuple[str, bytes, bool], ...]] = (
    ("a well-formed port.expose", expose_wire(UNDECLARED_PORT), False),
    ("a frame that is not a message", MALFORMED_FRAME, True),
)


@dataclass(frozen=True, slots=True)
class Attempt:
    """One Sandbox_Protocol request, and what came back."""

    when: str
    status: int
    #: Whether a Sandbox_Protocol message came back, which is whether anything was decoded.
    is_protocol_message: bool
    phase: RuntimePhase
    malformed: bool

    def describe(self) -> str:
        return f"{self.when} (phase {self.phase}) answered {self.status}"


@dataclass(frozen=True, slots=True)
class Baseline:
    """What a Sandbox has applied and published before `/run` is invoked. All of it nothing."""

    phase: RuntimePhase
    configuration: RunConfiguration | None
    values_present: bool
    declared: frozenset[int]


@dataclass(frozen=True, slots=True)
class Started:
    """One Sandbox, driven from construction through `/run` and observed at every step."""

    label: str
    delivery: Delivery
    baseline: Baseline
    before: tuple[Attempt, ...]
    during: tuple[Attempt, ...]
    after: tuple[Attempt, ...]
    status: int
    reason: str
    phase: RuntimePhase
    configuration: RunConfiguration | None
    values_present: bool
    declared: frozenset[int]
    #: What `port.expose` answers for every declared port and for one undeclared one. The applied
    #: configuration as a caller sees it, which is a stronger view than reading the object.
    exposed: Mapping[int, str]
    #: The filesystem tree a `restore` section produced, keyed by path relative to the root.
    tree: Mapping[str, bytes]
    #: Every reference the State_Store was asked for, in order.
    reads: tuple[str, ...]


# --- The State_Store, faked; the offline suite denies the real one -------------------------


class RecordingStateStore:
    """The State_Store read seam, answering from a dictionary and recording every reference.

    The same stand-in `tests/test_runtime_run_hook.py` uses, and for the same reason: the offline
    suite denies outbound network access, and neither the bucket nor the Sandbox execution role
    exists yet. `runtime.run_config` declares the seam as one method so that this is enough.
    """

    def __init__(self, objects: Mapping[str, bytes]) -> None:
        self._objects = dict(objects)
        self.reads: list[str] = []

    async def read(self, reference: str) -> bytes:
        self.reads.append(reference)
        stored = self._objects.get(reference)
        if stored is None:
            raise ReferenceNotFound(f"no object is stored at {reference}")
        return stored


# --- The runtimes: the real one, and the three defective ones the property must catch ------


class Deviation(enum.StrEnum):
    """A defective runtime, built to demonstrate that an assertion here can fail."""

    SECOND_PARSER = "a configuration path with a parser of its own"
    EAGER_GATE = "a gate opened before the configuration was applied"
    PRECONFIGURED = "a configuration applied before the /run hook ran"


def _parsed_leniently(document: bytes) -> RunConfiguration:
    """A second parser: it does not normalise the port set and ignores what it does not know.

    Both of those are the shape a real second implementation takes. Neither is exotic: an
    implementation that read `exposedPorts` straight through would differ from the runtime's only
    for a document whose ports are unordered or repeated, and one that ignored unknown keys would
    differ only for a document carrying one.
    """
    body = json.loads(document)
    ports = body.get("exposedPorts") or []
    return RunConfiguration(
        exposed_ports=tuple(int(port) for port in ports),
        endpoint_url_template=body.get("endpointUrlTemplate"),
    )


class _SecondParserLifecycle(SandboxLifecycle):
    """A runtime whose configuration path parses the document itself.

    Everything else is the real `SandboxLifecycle`: the same reader decides inline against
    by-reference and fetches the document, the same `_apply` publishes it, and the per-Session
    values are still generated inside the hook. Only the bytes-to-configuration step is a second
    implementation, which is the defect being demonstrated.
    """

    async def apply_configuration(self, payload: bytes) -> None:
        configuration = _parsed_leniently(await self._reader.document_of(payload))
        self._apply(configuration)
        self._configuration = configuration
        self._values = SessionValues.generate()


class _EagerlyOpeningLifecycle(SandboxLifecycle):
    """A runtime that opens the readiness gate before it applies anything.

    The gate transitions belong to `runtime.hooks` and an action that touches them can break a
    guarantee it does not own, which is what this demonstrates: `STARTING -> SERVING` is a legal
    transition, so nothing stops an action from making it early.
    """

    def __init__(
        self,
        *,
        gate: ReadinessGate,
        ports: ExposedPorts,
        filesystem_root: ConfinedRoot,
        state_store: RecordingStateStore,
        max_payload_bytes: int,
    ) -> None:
        super().__init__(
            ports=ports,
            filesystem_root=filesystem_root,
            state_store=state_store,
            max_payload_bytes=max_payload_bytes,
        )
        self._eager = gate

    async def apply_configuration(self, payload: bytes) -> None:
        await self._eager.finish_start()
        await super().apply_configuration(payload)


#: What a runtime that configured itself at construction time would have applied. A plausible
#: configuration, because the point is that it is applied at the wrong moment rather than that it
#: is wrong.
PRECONFIGURED: Final = RunConfiguration(
    exposed_ports=(8080,), endpoint_url_template=_template("baked-in")
)


class _PreconfiguredLifecycle(SandboxLifecycle):
    """A runtime that applied a per-Session configuration before `/run` was ever invoked."""

    def __init__(
        self,
        *,
        ports: ExposedPorts,
        filesystem_root: ConfinedRoot,
        state_store: RecordingStateStore,
        max_payload_bytes: int,
    ) -> None:
        super().__init__(
            ports=ports,
            filesystem_root=filesystem_root,
            state_store=state_store,
            max_payload_bytes=max_payload_bytes,
        )
        self._apply(PRECONFIGURED)
        self._configuration = PRECONFIGURED
        self._values = SessionValues.generate()


def _actions_for(
    deviation: Deviation | None,
    *,
    gate: ReadinessGate,
    ports: ExposedPorts,
    root: Path,
    store: RecordingStateStore,
    limit: int,
) -> SandboxLifecycle:
    """The runtime one Sandbox is built on: the real one, or one of the three defective ones."""
    filesystem_root = ConfinedRoot(root)
    if deviation is Deviation.SECOND_PARSER:
        return _SecondParserLifecycle(
            ports=ports,
            filesystem_root=filesystem_root,
            state_store=store,
            max_payload_bytes=limit,
        )
    if deviation is Deviation.EAGER_GATE:
        return _EagerlyOpeningLifecycle(
            gate=gate,
            ports=ports,
            filesystem_root=filesystem_root,
            state_store=store,
            max_payload_bytes=limit,
        )
    if deviation is Deviation.PRECONFIGURED:
        return _PreconfiguredLifecycle(
            ports=ports,
            filesystem_root=filesystem_root,
            state_store=store,
            max_payload_bytes=limit,
        )
    return SandboxLifecycle(
        ports=ports,
        filesystem_root=filesystem_root,
        state_store=store,
        max_payload_bytes=limit,
    )


# --- Probing the runtime from inside its own `/run` hook ----------------------------------


class _Probing:
    """The real lifecycle actions, with a Sandbox_Protocol probe on either side of `/run`'s work.

    A `LifecycleActions` implementation, which is all `create_app` asks for, wrapping another. The
    probe issues its requests through the application's own handler on the application's own event
    loop, which is the same call `POST /protocol` makes — `runtime.app` routes it as
    `_as_response(await handler.handle(await request.body()))` — so the status observed here is the
    status a caller would have received at that moment.

    Observations are recorded rather than asserted. An `AssertionError` raised here would be caught
    by `runtime.hooks`' fail-closed arm and returned as a 500, so the failure would be reported as
    a refused `/run` rather than as the assertion it is.
    """

    def __init__(self, inner: SandboxLifecycle) -> None:
        self._inner = inner
        self._handler: SandboxProtocolHandler | None = None
        self._gate: ReadinessGate | None = None
        self.observations: list[Attempt] = []

    def bind(self, handler: SandboxProtocolHandler, gate: ReadinessGate) -> None:
        """Bind what the probe needs, which exists only once the application has been built."""
        self._handler = handler
        self._gate = gate

    @property
    def inner(self) -> SandboxLifecycle:
        """The wrapped runtime, so a caller can read what it applied."""
        return self._inner

    async def apply_configuration(self, payload: bytes) -> None:
        await self._probe("inside /run, before the configuration is read")
        await self._inner.apply_configuration(payload)
        await self._probe("inside /run, after the configuration was applied")

    async def quiesce_and_flush(self) -> None:
        await self._inner.quiesce_and_flush()

    async def refresh_egress_identity(self) -> None:
        await self._inner.refresh_egress_identity()

    async def persist_artifacts(self) -> None:
        await self._inner.persist_artifacts()

    async def _probe(self, when: str) -> None:
        handler, gate = self._handler, self._gate
        assert handler is not None and gate is not None, "the probe was not bound"
        for label, wire, malformed in _PROBES:
            reply = await handler.handle(wire)
            self.observations.append(
                Attempt(
                    when=f"{when}, {label}",
                    status=reply.status,
                    is_protocol_message=reply.is_protocol_message,
                    phase=gate.phase,
                    malformed=malformed,
                )
            )


# --- Driving one Sandbox -------------------------------------------------------------------


def _payload(drawn: Drawn, delivery: Delivery) -> bytes:
    if delivery is Delivery.INLINE:
        return drawn.document
    return json.dumps({CONFIG_REFERENCE_KEY: CONFIG_REFERENCE}).encode()


def _objects(drawn: Drawn, delivery: Delivery) -> Mapping[str, bytes]:
    if delivery is Delivery.INLINE:
        return drawn.stored
    return {**drawn.stored, CONFIG_REFERENCE: drawn.document}


def _limit(drawn: Drawn, delivery: Delivery) -> int:
    """The provider-declared payload limit the Sandbox is built with.

    For the by-reference path this is the anchored ceiling, which is the provider the design names.
    For the inline path it is whatever the document needs, because the limit is a *provider's*
    declaration and the providers disagree — Lambda MicroVM declares 16,384 and the Fargate task
    provider 8,192 — so every document is inline on some deployment and by-reference on another,
    and R7.11's equality is a claim across those two. The ceiling itself is asserted separately,
    on the reader, by `assert_the_payload_limit_decides_the_delivery_path`.
    """
    if delivery is Delivery.BY_REFERENCE:
        return MAX_RUN_CONFIG_BYTES
    return max(MAX_RUN_CONFIG_BYTES, len(drawn.document))


def start(
    drawn: Drawn,
    delivery: Delivery,
    *,
    root: Path,
    label: str,
    deviation: Deviation | None = None,
) -> Started:
    """Build one Sandbox, observe it before `/run`, drive `/run`, and observe it after."""
    gate = ReadinessGate()
    ports = ExposedPorts(catalogue=CATALOGUE)
    store = RecordingStateStore(_objects(drawn, delivery))
    inner = _actions_for(
        deviation,
        gate=gate,
        ports=ports,
        root=root,
        store=store,
        limit=_limit(drawn, delivery),
    )

    probe = _Probing(inner)
    operations = OperationRegistry(catalogue=CATALOGUE)
    ports.register(operations)
    app = create_app(
        actions=probe, operations=operations, gate=gate, catalogue=CATALOGUE
    )
    handler = app.state.handler
    assert isinstance(handler, SandboxProtocolHandler)
    probe.bind(handler, gate)

    # A deviating runtime can leave the gate in a phase `runtime.hooks` then refuses to move,
    # which would surface as an exception through the transport rather than as the assertion
    # failure being demonstrated. The real runtime is driven with server exceptions raised.
    client = TestClient(app, raise_server_exceptions=deviation is None)
    with client:
        before = tuple(
            _http_attempt(
                client,
                gate,
                when=f"before /run, {name}",
                wire=wire,
                malformed=malformed,
            )
            for name, wire, malformed in _PROBES
        )
        baseline = Baseline(
            phase=gate.phase,
            configuration=inner.configuration,
            values_present=inner.values is not None,
            declared=ports.declared,
        )
        response = client.post(f"{HOOK_PATH_PREFIX}/run", content=_payload(drawn, delivery))
        after = tuple(
            _http_attempt(
                client, gate, when=f"after /run, {name}", wire=wire, malformed=malformed
            )
            for name, wire, malformed in _PROBES
        )
        # Two declared ports and the undeclared one. Two, not all of them: the URL is the
        # template with the port substituted, so a second port catches a divergence a first one
        # would not and a third catches nothing more, while the declared *set* is compared in
        # full off the registry.
        exposed = {
            port: _ask_to_expose(client, port)
            for port in (*sorted(ports.declared)[:2], UNDECLARED_PORT)
        }

    return Started(
        label=label,
        delivery=delivery,
        baseline=baseline,
        before=before,
        during=tuple(probe.observations),
        after=after,
        status=response.status_code,
        reason=response.text,
        phase=gate.phase,
        configuration=inner.configuration,
        values_present=inner.values is not None,
        declared=ports.declared,
        exposed=exposed,
        tree=_tree_of(root),
        reads=tuple(store.reads),
    )


def _http_attempt(
    client: TestClient,
    gate: ReadinessGate,
    *,
    when: str,
    wire: bytes,
    malformed: bool,
) -> Attempt:
    """Send one protocol request over the real HTTP transport and record what came back."""
    response = client.post(PROTOCOL_PATH, content=wire)
    return Attempt(
        when=when,
        status=response.status_code,
        is_protocol_message=response.headers.get("content-type") == CBOR_MEDIA_TYPE,
        phase=gate.phase,
        malformed=malformed,
    )


def _ask_to_expose(client: TestClient, port: int) -> str:
    """What `port.expose` answers for `port`, rendered so two Sandboxes can be compared.

    A refusal at the transport, a refused operation and a `port.url` all render, because all three
    are answers a caller can receive and the two delivery paths have to give the same one.
    """
    response = client.post(PROTOCOL_PATH, content=expose_wire(port))
    if response.headers.get("content-type") != CBOR_MEDIA_TYPE:
        return f"{response.status_code}: {response.text}"
    reply = decode(response.content, catalogue=CATALOGUE)
    t = reply[ENVELOPE_KEY_TYPE]
    body = reply[ENVELOPE_KEY_BODY]
    assert isinstance(t, str) and isinstance(body, dict)
    fields = {
        declared.name: body[declared.key]
        for declared in CATALOGUE.messages[t].body
        if declared.key in body
    }
    return f"{t} {fields}"


def _tree_of(root: Path) -> Mapping[str, bytes]:
    """Every regular file below `root`, keyed by its path relative to it."""
    return {
        str(path.relative_to(root)): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


# --- The assertions, each usable on its own ------------------------------------------------


def assert_nothing_is_applied_before_the_run_hook(started: Started) -> None:
    """R7.8's second sentence, read off the runtime rather than inferred from its behaviour."""
    baseline = started.baseline
    assert baseline.phase is RuntimePhase.CLOSED, (
        f"{started.label} is {baseline.phase} before /run was invoked; nothing serves the "
        f"Sandbox_Protocol until /run says so"
    )
    assert baseline.configuration is None, (
        f"{started.label} had applied {baseline.configuration} before /run was invoked, and "
        f"R7.8 forbids applying any per-Session configuration before the hook"
    )
    assert not baseline.values_present, (
        f"{started.label} had generated its per-Session values before /run was invoked; R7.12 "
        f"requires them generated while the hook executes"
    )
    assert baseline.declared == frozenset(), (
        f"{started.label} had published the port set {sorted(baseline.declared)} before /run "
        f"was invoked, so a configuration-derived value existed before the hook"
    )


def assert_no_protocol_request_succeeds_before_ready(started: Started) -> None:
    """R7.8's first sentence, quantified over the moment the request arrives.

    Every attempt made before `/run` answered — two over the HTTP transport before the hook was
    invoked, and two or four from inside the hook itself — is refused, and none of them produces a
    Sandbox_Protocol message, which is what "no request succeeds" means at this transport: nothing
    was decoded and nothing was served.
    """
    attempts = (*started.before, *started.during)
    assert len(attempts) >= 4, (
        f"{started.label} was probed at only {len(attempts)} moments; the timing quantification "
        f"is half the claim, so a run that reached neither side of the hook proves less than it "
        f"appears to"
    )
    for attempt in attempts:
        assert attempt.status == HTTPStatus.SERVICE_UNAVAILABLE, (
            f"{started.label}: {attempt.describe()}, but /run had not returned 200, so no "
            f"Sandbox_Protocol request may be served yet (R7.8)"
        )
        assert not attempt.is_protocol_message, (
            f"{started.label}: {attempt.describe()} with a Sandbox_Protocol message, so the "
            f"request was decoded and served rather than refused at the readiness gate"
        )
        assert attempt.phase is not RuntimePhase.SERVING, (
            f"{started.label}: {attempt.describe()} while the gate was already SERVING, so the "
            f"handler opened before /run returned"
        )


def assert_the_gate_is_checked_before_the_body_is_decoded(started: Started) -> None:
    """A closed runtime does no work on the bytes, and an open one does.

    The same undecodable frame is sent before `/run` and after it. Before, it must draw the
    readiness refusal — the gate is consulted first, so the bytes are never looked at. After a
    successful `/run` the same bytes must draw a decode error carrying a Sandbox_Protocol message,
    and after a failed one a terminal refusal. The second half is what keeps the first from being
    satisfied by a runtime that refuses everything forever.
    """
    early = [
        attempt for attempt in (*started.before, *started.during) if attempt.malformed
    ]
    assert early, f"{started.label} was never probed with an undecodable frame"
    for attempt in early:
        assert attempt.status == HTTPStatus.SERVICE_UNAVAILABLE, (
            f"{started.label}: {attempt.describe()}; an undecodable frame arriving at a closed "
            f"runtime is refused at the gate, not decoded and reported"
        )
        assert not attempt.is_protocol_message, (
            f"{started.label}: {attempt.describe()} with a message, so the frame was decoded "
            f"before the gate was consulted"
        )

    late = [attempt for attempt in started.after if attempt.malformed]
    assert late, (
        f"{started.label} was never probed with an undecodable frame after /run"
    )
    for attempt in late:
        if started.phase is RuntimePhase.SERVING:
            assert (
                attempt.status == HTTPStatus.BAD_REQUEST and attempt.is_protocol_message
            ), (
                f"{started.label}: {attempt.describe()}; the bytes that drew a readiness "
                f"refusal before /run must be decoded and reported now that the handler is "
                f"open, or the earlier refusal was not a readiness decision"
            )
        else:
            assert (
                attempt.status == HTTPStatus.GONE and not attempt.is_protocol_message
            ), (
                f"{started.label}: {attempt.describe()}; a runtime whose /run failed will never "
                f"serve, which the transport reports as 410 rather than 503"
            )


def assert_the_run_hook_matched_the_document(drawn: Drawn, started: Started) -> None:
    """`/run` returns 200 exactly for a document it applied, and applies nothing otherwise."""
    if drawn.applies:
        assert started.status == HTTPStatus.OK, (
            f"{started.label} refused {drawn.describe}: {started.reason}"
        )
        assert started.phase is RuntimePhase.SERVING, (
            f"{started.label} returned 200 with the gate {started.phase}, so 200 was returned "
            f"before the Sandbox was ready to accept requests (R7.8)"
        )
        assert started.configuration is not None and started.values_present, (
            f"{started.label} returned 200 having applied no configuration and generated no "
            f"per-Session values"
        )
        for port, answer in started.exposed.items():
            if port not in started.declared:
                continue
            assert answer.startswith("port.url"), (
                f"{started.label} is serving and declared port {port}, but port.expose "
                f"answered {answer}; the applied configuration is not observable"
            )
        return

    assert started.status != HTTPStatus.OK, (
        f"{started.label} returned 200 for {drawn.describe}"
    )
    assert started.phase is RuntimePhase.FAILED, (
        f"{started.label} refused {drawn.describe} and left the gate {started.phase}; a /run "
        f"that did not complete leaves the handler closed"
    )
    # R7.8's prohibition on the failure path, which is where a partly applied configuration would
    # be invisible: the gate admits nothing, so only these three readings can show it.
    assert started.configuration is None, (
        f"{started.label} refused {drawn.describe} having applied {started.configuration}"
    )
    assert not started.values_present, (
        f"{started.label} refused {drawn.describe} having published per-Session values"
    )
    assert started.declared == frozenset(), (
        f"{started.label} refused {drawn.describe} having published the port set "
        f"{sorted(started.declared)}"
    )


def assert_the_payload_limit_decides_the_delivery_path(drawn: Drawn) -> None:
    """R7.11's decision, on the reader alone: no State_Store, and nothing applied.

    `reference_in` exists separately so this is assertable without a Sandbox, and the boundary is
    the interesting part: a document *at* the limit is carried inline and one above it is not,
    which is the whole reason the reference path exists.
    """
    reader = RunConfigurationReader(max_payload_bytes=MAX_RUN_CONFIG_BYTES)
    envelope = json.dumps({CONFIG_REFERENCE_KEY: CONFIG_REFERENCE}).encode()
    assert reader.reference_in(envelope) == CONFIG_REFERENCE, (
        "the by-reference envelope is not being read as one"
    )
    if not drawn.is_json_object:
        return
    assert reader.reference_in(drawn.document) is None, (
        f"{drawn.describe} was read as a reference envelope; a payload carrying no "
        f"{CONFIG_REFERENCE_KEY} is the configuration document itself"
    )
    if drawn.band is Band.ABOVE:
        with pytest.raises(
            ConfigurationError, match="exceeds the provider-declared limit"
        ):
            asyncio.run(reader.document_of(drawn.document))
        return
    assert asyncio.run(reader.document_of(drawn.document)) == drawn.document, (
        f"{drawn.describe} was not carried inline, but it is within the provider-declared "
        f"limit of {MAX_RUN_CONFIG_BYTES} bytes"
    )


def assert_applied_alike(inline: Started, fetched: Started) -> None:
    """R7.11: the same document applies the same configuration whichever way it was delivered.

    Four views of "the applied configuration", because one of them alone would be weaker than the
    claim: the object each runtime holds, the port set each published, the URL `port.expose`
    answers with for each port, and the filesystem tree a `restore` section produced.
    """
    assert inline.status == fetched.status, (
        f"{inline.delivery} answered {inline.status} and {fetched.delivery} answered "
        f"{fetched.status} for one document\n  inline: {inline.reason}\n  fetched: "
        f"{fetched.reason}"
    )
    assert inline.phase is fetched.phase, (
        f"one document left the gate {inline.phase} {inline.delivery} and {fetched.phase} "
        f"{fetched.delivery}"
    )
    assert inline.configuration == fetched.configuration, (
        f"one document applied {inline.configuration} {inline.delivery} and "
        f"{fetched.configuration} {fetched.delivery}; the delivery path is a fact about the "
        f"transport and must not be one about the Session (R7.11)"
    )
    assert inline.values_present == fetched.values_present, (
        f"one document generated per-Session values {inline.delivery} but not {fetched.delivery}"
    )
    assert inline.declared == fetched.declared, (
        f"one document published {sorted(inline.declared)} {inline.delivery} and "
        f"{sorted(fetched.declared)} {fetched.delivery}"
    )
    if inline.phase is RuntimePhase.SERVING:
        assert dict(inline.exposed) == dict(fetched.exposed), (
            f"port.expose answers differently for one document depending on how it was "
            f"delivered\n  {inline.delivery}: {dict(inline.exposed)}\n"
            f"  {fetched.delivery}: {dict(fetched.exposed)}"
        )
    else:
        # Neither runtime is serving, so every answer is the gate's retained refusal rather than
        # anything the configuration decided. The status is compared here; the reason it carries
        # is compared by `assert_refused_alike`, which is where the one documented exception to
        # reason equality lives.
        assert _refusal_statuses(inline.exposed) == _refusal_statuses(
            fetched.exposed
        ), (
            f"port.expose is refused differently for one document depending on how it was "
            f"delivered\n  {inline.delivery}: {dict(inline.exposed)}\n"
            f"  {fetched.delivery}: {dict(fetched.exposed)}"
        )
    assert dict(inline.tree) == dict(fetched.tree), (
        f"one document restored {sorted(inline.tree)} {inline.delivery} and "
        f"{sorted(fetched.tree)} {fetched.delivery}"
    )


def _refusal_statuses(exposed: Mapping[int, str]) -> Mapping[int, str]:
    """The status each `port.expose` answer carried, without the reason attached to it."""
    return {port: answer.split(":", 1)[0] for port, answer in exposed.items()}


def assert_refused_alike(drawn: Drawn, inline: Started, fetched: Started) -> None:
    """A refused document is refused with the same sentence, whichever way it arrived.

    The sharpest available form of "there is no second parser": both paths hand identical bytes to
    `parse_configuration`, so the refusal has to be identical too. Excluded are the four defects
    that fail before the document is reached, where the two paths are describing different things —
    an inline payload that is not a JSON object is refused as "the run hook payload" and the same
    bytes fetched by reference are refused as "the per-Session configuration". The noun differs
    because it should; the applied configuration, compared unconditionally above, does not.
    """
    if drawn.applies or drawn.defect in _BEFORE_THE_DOCUMENT:
        return
    assert inline.reason == fetched.reason, (
        f"{drawn.describe} was refused with two different reasons\n"
        f"  {inline.delivery}: {inline.reason}\n"
        f"  {fetched.delivery}: {fetched.reason}"
    )


def assert_the_delivery_path_taken_was_the_one_asked_for(
    inline: Started, fetched: Started
) -> None:
    """The paths were actually distinct, observed at the State_Store rather than assumed."""
    assert CONFIG_REFERENCE not in inline.reads, (
        f"the inline Sandbox read {CONFIG_REFERENCE} from the State_Store, so it did not take "
        f"the inline path and the two Sandboxes are not comparing two paths"
    )
    assert fetched.reads[:1] == (CONFIG_REFERENCE,), (
        f"the by-reference Sandbox's first State_Store read was {fetched.reads[:1]}, not the "
        f"configuration reference; the configuration must be retrieved before anything else"
    )


# --- Fresh filesystem roots ----------------------------------------------------------------


@dataclass(slots=True)
class Roots:
    """A source of one fresh filesystem root per Sandbox.

    Module-scoped, because a `/run` that restores state writes into its root and two Sandboxes
    sharing one would compare a tree neither of them alone produced.
    """

    base: Path
    handed_out: int = 0

    def fresh(self, label: str) -> Path:
        self.handed_out += 1
        root = self.base / f"{self.handed_out:05d}-{label}"
        root.mkdir(parents=True)
        return root


@pytest.fixture(scope="module")
def roots(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Roots]:
    yield Roots(tmp_path_factory.mktemp("property-9"))


# --- The property --------------------------------------------------------------------------


#: The eighteen document shapes the property is parametrised over: the applicable one, and each
#: named defect. Every one runs the design's iteration floor over the drawn axes, so the whole
#: property runs 1,800 examples.
SHAPES: Final = (None, *Defect)


# Feature: aws-serverless-agent-sandbox, Property 9: For all per-Session configurations, no
# Sandbox_Protocol request succeeds before the /run hook returns 200 and no configuration-derived
# value is observable before it; and for all configurations, the applied configuration is
# identical whether it was delivered inline or by reference from the State_Store.
@pytest.mark.parametrize(
    "defect",
    SHAPES,
    ids=[shape.name.lower() if shape is not None else "applicable" for shape in SHAPES],
)
@given(data=st.data())
@settings(max_examples=MINIMUM_EXAMPLES)
def test_readiness_gating_and_configuration_path_equivalence(
    data: st.DataObject, defect: Defect | None, roots: Roots
) -> None:
    drawn = data.draw(run_config(defect))
    inline = start(
        drawn,
        Delivery.INLINE,
        root=roots.fresh("inline"),
        label="the inline Sandbox",
    )
    fetched = start(
        drawn,
        Delivery.BY_REFERENCE,
        root=roots.fresh("fetched"),
        label="the by-reference Sandbox",
    )

    for started in (inline, fetched):
        assert_nothing_is_applied_before_the_run_hook(started)
        assert_no_protocol_request_succeeds_before_ready(started)
        assert_the_gate_is_checked_before_the_body_is_decoded(started)
        assert_the_run_hook_matched_the_document(drawn, started)

    assert_the_payload_limit_decides_the_delivery_path(drawn)
    assert_the_delivery_path_taken_was_the_one_asked_for(inline, fetched)
    assert_applied_alike(inline, fetched)
    assert_refused_alike(drawn, inline, fetched)


# --- Non-vacuity: the three defective runtimes, run against the property's own assertions ---


def applicable(
    *,
    ports: list[int] | None = None,
    host: str = "sandbox-1",
    extra: Mapping[str, object] | None = None,
) -> Drawn:
    """One hand-written document, in the same shape the generator produces."""
    body: dict[str, object] = {"endpointUrlTemplate": _template(host)}
    if ports is not None:
        body["exposedPorts"] = ports
    if extra is not None:
        body.update(extra)
    return Drawn(
        document=json.dumps(body).encode(),
        band=Band.BELOW,
        defect=None,
        stored={},
        applies=True,
    )


def _fails(check: Callable[[], None]) -> str:
    """Run a check that must fail, and return the reason it gave.

    `pytest.raises` would say only that something failed. What matters for a non-vacuity
    demonstration is *which* assertion caught the defect, so the message is returned to be
    asserted on.
    """
    try:
        check()
    except AssertionError as failure:
        return str(failure)
    raise AssertionError(
        "the check passed against a runtime built to violate it, so the property is asserting "
        "nothing about that defect"
    )


def test_a_second_parser_on_the_by_reference_path_is_caught(roots: Roots) -> None:
    """A configuration path with a parser of its own fails the equivalence assertion.

    The document declares its ports unordered and repeated and carries a `persist` section. The
    runtime's own parser sorts and de-duplicates the ports and reads the section; the second parser
    does neither, and that is the entire difference between the two runtimes.
    """
    drawn = applicable(
        ports=[8080, 3000, 8080],
        extra={"persist": {"reference": PERSIST_REFERENCE, "compress": True}},
    )
    inline = start(
        drawn,
        Delivery.INLINE,
        root=roots.fresh("vacuity-inline"),
        label="the inline Sandbox",
    )
    fetched = start(
        drawn,
        Delivery.BY_REFERENCE,
        root=roots.fresh("vacuity-second-parser"),
        label="the by-reference Sandbox",
        deviation=Deviation.SECOND_PARSER,
    )

    assert inline.status == HTTPStatus.OK and fetched.status == HTTPStatus.OK
    reason = _fails(lambda: assert_applied_alike(inline, fetched))
    assert "applied" in reason
    assert "must not be one about the Session" in reason


def test_an_inline_shortcut_that_accepts_more_is_caught(roots: Roots) -> None:
    """An inline path that skips a check the fetched path performs fails the same assertion.

    The document carries a misspelled key. The runtime refuses it, because applying it would apply
    less than was asked for; the shortcut ignores what it does not recognise and returns 200. The
    two paths then disagree about whether the document is a configuration at all.
    """
    drawn = applicable(ports=[8080], extra={"exposedPort": [9090]})
    inline = start(
        drawn,
        Delivery.INLINE,
        root=roots.fresh("vacuity-shortcut"),
        label="the inline Sandbox",
        deviation=Deviation.SECOND_PARSER,
    )
    fetched = start(
        drawn,
        Delivery.BY_REFERENCE,
        root=roots.fresh("vacuity-fetched"),
        label="the by-reference Sandbox",
    )

    assert inline.status == HTTPStatus.OK
    assert fetched.status != HTTPStatus.OK
    assert "does not understand" in fetched.reason
    reason = _fails(lambda: assert_applied_alike(inline, fetched))
    assert "answered" in reason


def test_a_gate_opened_before_the_configuration_was_applied_is_caught(
    roots: Roots,
) -> None:
    """The third probe moment is load-bearing, and this is the runtime it exists to catch.

    Nothing else here notices. The gate transitions are legal, `/run` applies the configuration it
    was given, and a request arriving before the hook was invoked is still refused. The only
    observation that fails is the one taken from inside the hook after the configuration was
    applied and before 200 was returned.
    """
    drawn = applicable(ports=[8080])
    started = start(
        drawn,
        Delivery.INLINE,
        root=roots.fresh("vacuity-eager-gate"),
        label="the eagerly opening Sandbox",
        deviation=Deviation.EAGER_GATE,
    )

    assert_nothing_is_applied_before_the_run_hook(started)
    for attempt in started.before:
        assert attempt.status == HTTPStatus.SERVICE_UNAVAILABLE

    reason = _fails(lambda: assert_no_protocol_request_succeeds_before_ready(started))
    assert "after the configuration was applied" in reason


def test_a_configuration_applied_before_the_run_hook_is_caught(roots: Roots) -> None:
    """R7.8's second sentence is non-vacuous: a runtime that configured itself early fails it.

    Note what still holds for this runtime: no protocol request succeeds before `/run` returns,
    because the readiness gate refuses admission whatever has been configured behind it. That is
    the design's reason for making the gate the mechanism, and it is also why the prohibition has
    to be asserted by reading the runtime rather than by probing it.
    """
    drawn = applicable(ports=[8080])
    started = start(
        drawn,
        Delivery.INLINE,
        root=roots.fresh("vacuity-preconfigured"),
        label="the preconfigured Sandbox",
        deviation=Deviation.PRECONFIGURED,
    )

    assert_no_protocol_request_succeeds_before_ready(started)

    reason = _fails(lambda: assert_nothing_is_applied_before_the_run_hook(started))
    assert "before /run was invoked" in reason


def test_the_padding_changes_the_size_and_nothing_else() -> None:
    """The size bands are real, and the vehicle that makes them is meaning-preserving.

    Whitespace padding is what lets one logical document be drawn below, at and above the payload
    limit, so the comparison across the bands is a comparison of the same input. If padding
    changed the configuration, every band would be a different document and the generator's whole
    span would be an illusion.
    """
    document = json.dumps(
        {"exposedPorts": [8080], "endpointUrlTemplate": _template("sandbox-1")}
    ).encode()
    at_limit = _sized(document, MAX_RUN_CONFIG_BYTES)
    above = _sized(document, MAX_RUN_CONFIG_BYTES + 1)

    assert len(at_limit) == MAX_RUN_CONFIG_BYTES
    assert len(above) == MAX_RUN_CONFIG_BYTES + 1
    assert parse_configuration(document) == parse_configuration(at_limit)
    assert parse_configuration(document) == parse_configuration(above)

    # And a padded undecodable payload stays undecodable, which is what keeps a defective document
    # defective across all three bands.
    for defect, raw in _RAW_PAYLOADS.items():
        if defect is Defect.EMPTY_PAYLOAD:
            continue
        with pytest.raises(ConfigurationError):
            parse_configuration(_sized(raw, MAX_RUN_CONFIG_BYTES))


def test_every_named_defect_has_a_document_shape() -> None:
    """`_spoil` handles every member of `Defect`, so no member is silently unreachable.

    The property is parametrised over `Defect`, so a member with no shape would raise rather than
    pass — but it would raise inside a Hypothesis example, which is a longer road to the same
    fact. This says it directly.
    """
    for defect in Defect:
        if defect in _RAW_PAYLOADS:
            continue
        body: dict[str, object] = {"endpointUrlTemplate": _template("sandbox-1")}
        _spoil(body, {}, defect, host="sandbox-1")
        assert body != {"endpointUrlTemplate": _template("sandbox-1")}, (
            f"{defect} left the document untouched, so the property's parametrisation over it "
            f"is testing an applicable document under a defective name"
        )
