# kiro-classification: public
"""The run hook payload: one configuration document, delivered inline or by reference (R7.11).

R7.11 is a size rule with a mechanism attached. Above the payload limit the provider will carry,
the configuration travels as a State_Store reference and the Sandbox_Runtime retrieves it itself.
The design puts the runtime's half in one sentence — "if it carries a `configRef` rather than
inline configuration, fetch the configuration from the State_Store under that reference" — and the
Compute_Provider's half already exists: `control_plane.providers.lambda_microvm._run_hook_payload`
sends `spec.start_config` verbatim when it fits and `{"startConfigRef": "..."}` when it does not.
This module is the other end of exactly that wire.

## Why the two paths cannot drift

The delivery path is a fact about the *transport*, and the applied configuration must be a fact
about the *Session*. So the paths meet immediately: both produce a `bytes` document and both hand
it to `parse_configuration`, which is the only function in the runtime that turns bytes into a
`RunConfiguration`. There is no second parser, no "inline shortcut" that skips a check the fetched
path performs, and no field that only one path can express. Equal document bytes therefore give
equal configurations by construction rather than by two implementations agreeing, which is what
makes the equivalence half of the design's Property 9 an assertion about one function instead of a
comparison of two code paths.

The reference envelope and the configuration document are also kept distinct on purpose. The
envelope has exactly one key and carries no configuration of its own, so there is no way to send
half the configuration inline and half by reference — a shape that would have two answers to
"what was applied" and no way to choose between them.

## The limit is the provider's, and it is a defect check

`ProviderLimits.max_run_config_bytes` is where the number comes from, and the providers already
refuse to provision a Sandbox whose inline configuration exceeds it. The runtime checking it again
is therefore not a second gate on caller input: it is the runtime declining to guess when it is
handed a payload its provider said it would not carry, which means either the payload was
truncated in transit or the provider and the runtime disagree about the limit. Both are defects
and both are better reported than absorbed, because a truncated JSON document usually fails to
parse but a truncated one that happens to parse would apply a configuration nobody composed.

The number is spelled here rather than imported from `control_plane.providers`. That is not
duplication to be tidied away later: this module runs inside the MicroVM, which the design places
firmly on the untrusted side of the boundary, and the provider package runs outside it in the
Control_Plane's execution role. Nothing in `runtime/` imports `control_plane/`, and a shared
constant module would be the first thing to cross that line for the sake of one integer. The
default is the anchored 16 KB ceiling; a deployment on a provider that declares less — the Fargate
task provider declares 8 KB — passes its own.

## The State_Store read is a seam

Fetching by reference needs a State_Store client with the Sandbox execution role's credentials,
reading the artifact prefix that role is confined to. Neither the bucket nor the role exists yet:
the IaC package is phase 12 and the Control_Plane that composes these documents is phase 6. So
`StateStoreReader` is one method, and the two failures a reader can distinguish from the outside —
the reference is not there, and reading it was denied — are distinct exception types, because
R13.7 asks the restoration failure to be *identified* and "absent" and "denied" have different
causes and different operator responses. Everything else a transport can do is the base type.

This is the same stance `runtime.ports` takes with `PortRouting`, and for the same reason: a
concrete client here would have to name a bucket, and a fabricated bucket name is indistinguish-
able from a real one until it reaches production.

## Two halves of one document, read by two hooks

The document carries what the `/run` hook applies *and* what the `/terminate` hook writes, which
is why `restore` and `persist` sit side by side here. Both are per-Session, both are composed by
the Control_Plane, and both are delivered by the same payload — there is no second document and no
second delivery path, so a Session cannot be configured to restore from somewhere and then be
unable to say where its output goes.

They are separate objects rather than one, because they are not symmetric in the fields that
matter. `restore` carries the size and digest the *writer* recorded, which only the previous
generation could know; `persist` carries the deadline and the path set, which only this generation
is subject to. A single object would have to make each field optional in the direction it does not
apply, and then "which fields are meaningful" would be a rule a reader had to remember rather than
a shape the schema states.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Final, Protocol, runtime_checkable

__all__ = [
    "CONFIG_REFERENCE_KEY",
    "DEFAULT_PERSIST_DEADLINE_MS",
    "MAX_PERSIST_DEADLINE_MS",
    "MAX_RUN_CONFIG_BYTES",
    "ConfigurationError",
    "PersistRequest",
    "ReadDenied",
    "ReferenceNotFound",
    "RestoreRequest",
    "RunConfiguration",
    "RunConfigurationReader",
    "StateReadFailure",
    "StateStoreReader",
    "parse_configuration",
]

#: The one key of the by-reference envelope, spelled as the provider spells it. A payload
#: carrying it is a reference and carries nothing else; a payload without it is the document.
CONFIG_REFERENCE_KEY: Final = "startConfigRef"

#: The anchored `runHookPayload` ceiling, which the Lambda MicroVM provider declares as its
#: `max_run_config_bytes`. See the module docstring for why it is spelled here.
MAX_RUN_CONFIG_BYTES: Final = 16_384

#: The document's keys. Named constants rather than string literals at each use, so the schema
#: this module accepts and the errors it reports cannot disagree about a spelling.
_EXPOSED_PORTS: Final = "exposedPorts"
_ENDPOINT_URL_TEMPLATE: Final = "endpointUrlTemplate"
_RESTORE: Final = "restore"
_PERSIST: Final = "persist"
_REFERENCE: Final = "reference"
_SIZE_BYTES: Final = "sizeBytes"
_SHA256: Final = "sha256"
_PATHS: Final = "paths"
_DEADLINE_MS: Final = "deadlineMs"
_COMPRESS: Final = "compress"

_DOCUMENT_KEYS: Final = frozenset(
    {_EXPOSED_PORTS, _ENDPOINT_URL_TEMPLATE, _RESTORE, _PERSIST}
)
_RESTORE_KEYS: Final = frozenset({_REFERENCE, _SIZE_BYTES, _SHA256})
_PERSIST_KEYS: Final = frozenset({_REFERENCE, _PATHS, _DEADLINE_MS, _COMPRESS})

#: How long the `/terminate` hook's artifact write may take when the document does not say.
#: A number rather than "no limit", because the design's reason for bounding it is that a hung
#: terminate hook leaves a billable Sandbox allocated, and an unbounded default would make the
#: bound something every composer had to remember to ask for.
DEFAULT_PERSIST_DEADLINE_MS: Final = 20_000

#: The longest deadline this runtime will accept. A configuration asking for more is refused
#: rather than clamped: clamping would apply a deadline nobody composed and report success, and
#: the composer would learn the number it asked for was ignored only from a truncated artifact.
#: This is the runtime's own ceiling and not a provider-declared one — no provider declares a
#: terminate hook budget — so it is spelled here as the point past which the bound stops bounding
#: anything worth bounding.
MAX_PERSIST_DEADLINE_MS: Final = 120_000

#: The port range the protocol catalogue also constrains `port.expose` to, checked here as well
#: because a configuration declaring port 0 would produce a port set no request could ever name.
_MIN_PORT: Final = 1
_MAX_PORT: Final = 65535

#: A SHA-256 digest, lowercase hex.
_DIGEST_LENGTH: Final = 64
_HEX_DIGITS: Final = frozenset("0123456789abcdef")


class ConfigurationError(Exception):
    """The run hook payload is not a configuration this runtime can apply.

    Deliberately *not* a `RestorationFailure`: R13.7 is about state that could not be restored,
    and a malformed payload has not reached restoration. `LifecycleHooks.run` catches this with
    the same fail-closed arm it uses for every other unexpected failure, so the gate stays closed
    and the reason travels back in a non-200 — which is what R7.8 requires and all it requires.
    """


class StateReadFailure(Exception):
    """Reading a reference from the State_Store failed.

    Raised by a `StateStoreReader` implementation. The reason is the sentence the operator will
    read, so it names what could not be read rather than restating that something went wrong.
    """

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class ReferenceNotFound(StateReadFailure):
    """No object exists in the State_Store under the reference."""


class ReadDenied(StateReadFailure):
    """The Sandbox execution role may not read the reference.

    Distinct from `ReferenceNotFound` because it is the failure a reference belonging to another
    Session produces: the per-Session execution role is confined to its own artifact prefix, so
    the denial comes from IAM rather than from a check this runtime performs. That distinction is
    why this module does not parse a reference to see whose it is — the reference is opaque here,
    and the authority on who may read it is the credential, not a string comparison inside the
    MicroVM.
    """


@runtime_checkable
class StateStoreReader(Protocol):
    """Reads an object out of the State_Store by opaque reference.

    One method, because that is the entire dependency: the runtime holds a reference it never
    parses, and the deployment holds the bucket, the credentials and the transport.
    """

    async def read(self, reference: str) -> bytes:
        """Return the bytes stored under `reference`.

        Raises:
            ReferenceNotFound: nothing is stored under the reference.
            ReadDenied: the Sandbox may not read it.
            StateReadFailure: the read failed for any other reason.
        """
        ...


@dataclass(frozen=True, slots=True)
class RestoreRequest:
    """Previously persisted state the `/run` hook must restore before readiness (R13.4).

    `size_bytes` and `sha256` are optional and are the difference between "the restore failed"
    and a reason that identifies *how*: a fetch that returns fewer bytes than were written is a
    truncated transfer, and one that returns the right number of the wrong bytes is corruption.
    Neither is detectable from the archive alone, so both come from the composer of this document,
    which is the side that wrote the artifact and knows what it wrote.
    """

    reference: str
    size_bytes: int | None = None
    sha256: str | None = None


@dataclass(frozen=True, slots=True)
class PersistRequest:
    """The Session output artifacts the `/terminate` hook writes to the State_Store (R13.3).

    `paths` is empty for "the whole configured filesystem root", which is the configuration of a
    Session that wants everything it produced kept. A non-empty set names what to keep, relative to
    that root, because that is where the previous generation's state was restored to and where the
    next one's will be — an absolute path in a persisted tree would mean something different on a
    Sandbox whose root is configured elsewhere, so absolute paths are refused.

    They are `str` rather than `bytes` despite `runtime.filesystem`'s byte-typed stance, because
    this document is JSON and JSON has no byte strings. `runtime.persist` encodes them with
    `os.fsencode` before resolving them, which is the same conversion `runtime.restore` performs on
    an archive member's name, so a name that is not valid UTF-8 survives a persist and a restore
    even though it cannot be *named* in this document.

    `deadline_ms` bounds the whole write, and `compress` selects between the two archive forms
    `runtime.restore` reads. Both have defaults, so the minimum viable `persist` is a reference.
    """

    reference: str
    paths: tuple[str, ...] = ()
    deadline_ms: int = DEFAULT_PERSIST_DEADLINE_MS
    compress: bool = False


@dataclass(frozen=True, slots=True)
class RunConfiguration:
    """The per-Session configuration one `/run` applies.

    Frozen, and compared by value, because "the applied configuration is identical whether it was
    delivered inline or by reference" is a statement about equality of these objects.
    """

    exposed_ports: tuple[int, ...] = ()
    endpoint_url_template: str | None = None
    restore: RestoreRequest | None = None
    persist: PersistRequest | None = None


def parse_configuration(document: bytes) -> RunConfiguration:
    """Read a configuration document. The only bytes-to-configuration function in the runtime.

    Both delivery paths call this and neither adds to it, which is what keeps them equivalent.

    Unknown keys are refused rather than ignored. A Session whose document carries a misspelled
    key would otherwise start successfully having applied less than was asked of it, and the
    absence would surface much later as a port that cannot be exposed or state that was never
    restored — a failure a long way from its cause.

    Raises:
        ConfigurationError: the document is not readable, or is not a configuration.
    """
    body = _object_of(document, "the per-Session configuration")
    _reject_unknown(body, _DOCUMENT_KEYS, "configuration")
    return RunConfiguration(
        exposed_ports=_ports_of(body.get(_EXPOSED_PORTS)),
        endpoint_url_template=_template_of(body.get(_ENDPOINT_URL_TEMPLATE)),
        restore=_restore_of(body.get(_RESTORE)),
        persist=_persist_of(body.get(_PERSIST)),
    )


class RunConfigurationReader:
    """Turns a run hook payload into a configuration, whichever way it was delivered (R7.11)."""

    def __init__(
        self,
        *,
        source: StateStoreReader | None = None,
        max_payload_bytes: int = MAX_RUN_CONFIG_BYTES,
    ) -> None:
        """Bind the State_Store reader and the provider-declared payload limit.

        `source` defaults to None, which is a runtime that can serve the inline path and refuses
        the by-reference one with that as the reason. That is a truthful configuration rather than
        a convenient one — a Sandbox started with no State_Store credentials genuinely cannot
        retrieve a reference — and it keeps the offline suite from needing a client it has no
        bucket for.
        """
        if max_payload_bytes < 1:
            raise ValueError(
                f"a provider-declared run config limit is a positive number of bytes: "
                f"{max_payload_bytes}"
            )
        self._source = source
        self._max_payload_bytes = max_payload_bytes

    @property
    def max_payload_bytes(self) -> int:
        """The provider-declared payload limit this reader keys the delivery decision off."""
        return self._max_payload_bytes

    def reference_in(self, payload: bytes) -> str | None:
        """The State_Store reference the payload carries, or None when it carries the document.

        Separate from `read` so that the decision R7.11 turns on is assertable on its own,
        without a State_Store reader and without applying anything.
        """
        body = _object_of(payload, "the run hook payload")
        if CONFIG_REFERENCE_KEY not in body:
            return None
        _reject_unknown(body, frozenset({CONFIG_REFERENCE_KEY}), "reference envelope")
        reference = body[CONFIG_REFERENCE_KEY]
        if not isinstance(reference, str) or not reference:
            raise ConfigurationError(
                f"{CONFIG_REFERENCE_KEY} must be a non-empty State_Store reference"
            )
        return reference

    async def read(self, payload: bytes) -> RunConfiguration:
        """Read the configuration this payload delivers.

        Raises:
            ConfigurationError: the payload or the document it names is not applicable.
        """
        return parse_configuration(await self.document_of(payload))

    async def document_of(self, payload: bytes) -> bytes:
        """The configuration document bytes, fetched first when the payload is a reference.

        The limit applies to the payload and never to the fetched document: carrying more than
        the provider will carry is the whole reason the reference exists, so a document bounded by
        the same number would leave R7.11 with nothing to do.
        """
        reference = self.reference_in(payload)
        if reference is None:
            if len(payload) > self._max_payload_bytes:
                raise ConfigurationError(
                    f"the run hook payload is {len(payload)} bytes, which exceeds the "
                    f"provider-declared limit of {self._max_payload_bytes}; configuration that "
                    f"large is delivered as a {CONFIG_REFERENCE_KEY}"
                )
            return payload
        if self._source is None:
            raise ConfigurationError(
                f"the payload carries a {CONFIG_REFERENCE_KEY} but this runtime has no "
                f"State_Store reader configured, so the configuration cannot be retrieved"
            )
        try:
            return await self._source.read(reference)
        except StateReadFailure as exc:
            raise ConfigurationError(
                f"retrieving the configuration from {reference!r} failed: {exc.reason}"
            ) from exc


# --- Reading one field at a time ---------------------------------------------------------


def _object_of(raw: bytes, described: str) -> dict[str, object]:
    """Decode `raw` as a JSON object, or say why it is not one."""
    if not raw:
        raise ConfigurationError(f"{described} is empty")
    try:
        decoded = json.loads(raw)
    except ValueError as exc:
        # `json.JSONDecodeError` and `UnicodeDecodeError` are both `ValueError`, and the
        # difference between "not UTF-8" and "not JSON" is already in the message.
        raise ConfigurationError(f"{described} is not readable JSON: {exc}") from exc
    if not isinstance(decoded, dict):
        raise ConfigurationError(
            f"{described} must be a JSON object, not {type(decoded).__name__}"
        )
    return {str(key): value for key, value in decoded.items()}


def _reject_unknown(
    body: dict[str, object], known: frozenset[str], described: str
) -> None:
    unknown = sorted(set(body) - known)
    if unknown:
        raise ConfigurationError(
            f"the {described} carries keys this runtime does not understand: {unknown}; "
            f"applying it would apply less than was asked for"
        )


def _ports_of(raw: object) -> tuple[int, ...]:
    """The declared exposed port set: sorted, de-duplicated, and in range."""
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise ConfigurationError(
            f"{_EXPOSED_PORTS} must be a list of port numbers, not {type(raw).__name__}"
        )
    ports: set[int] = set()
    for element in raw:
        if isinstance(element, bool) or not isinstance(element, int):
            raise ConfigurationError(
                f"{_EXPOSED_PORTS} contains {element!r}, which is not a port number"
            )
        if not _MIN_PORT <= element <= _MAX_PORT:
            raise ConfigurationError(
                f"{_EXPOSED_PORTS} contains the out-of-range port {element}"
            )
        ports.add(element)
    # Sorted so that two documents differing only in the order or the repetition of their ports
    # apply the same configuration, which is the equality the delivery paths are compared on.
    return tuple(sorted(ports))


def _template_of(raw: object) -> str | None:
    if raw is None:
        return None
    if not isinstance(raw, str) or not raw:
        raise ConfigurationError(
            f"{_ENDPOINT_URL_TEMPLATE} must be a non-empty URL template"
        )
    return raw


def _restore_of(raw: object) -> RestoreRequest | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ConfigurationError(
            f"{_RESTORE} must be an object naming previously persisted state, "
            f"not {type(raw).__name__}"
        )
    body = {str(key): value for key, value in raw.items()}
    _reject_unknown(body, _RESTORE_KEYS, f"{_RESTORE} object")
    reference = body.get(_REFERENCE)
    if not isinstance(reference, str) or not reference:
        raise ConfigurationError(
            f"{_RESTORE}.{_REFERENCE} must be a non-empty State_Store reference"
        )
    return RestoreRequest(
        reference=reference,
        size_bytes=_size_of(body.get(_SIZE_BYTES)),
        sha256=_digest_of(body.get(_SHA256)),
    )


def _size_of(raw: object) -> int | None:
    if raw is None:
        return None
    if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
        raise ConfigurationError(
            f"{_RESTORE}.{_SIZE_BYTES} must be a non-negative byte count, not {raw!r}"
        )
    return raw


def _digest_of(raw: object) -> str | None:
    if raw is None:
        return None
    if (
        not isinstance(raw, str)
        or len(raw) != _DIGEST_LENGTH
        or not set(raw) <= _HEX_DIGITS
    ):
        raise ConfigurationError(
            f"{_RESTORE}.{_SHA256} must be a SHA-256 digest as {_DIGEST_LENGTH} "
            f"lowercase hex digits"
        )
    return raw


def _persist_of(raw: object) -> PersistRequest | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ConfigurationError(
            f"{_PERSIST} must be an object naming the Session output artifacts to write, "
            f"not {type(raw).__name__}"
        )
    body = {str(key): value for key, value in raw.items()}
    _reject_unknown(body, _PERSIST_KEYS, f"{_PERSIST} object")
    reference = body.get(_REFERENCE)
    if not isinstance(reference, str) or not reference:
        raise ConfigurationError(
            f"{_PERSIST}.{_REFERENCE} must be a non-empty State_Store reference"
        )
    return PersistRequest(
        reference=reference,
        paths=_persist_paths_of(body.get(_PATHS)),
        deadline_ms=_persist_deadline_of(body.get(_DEADLINE_MS)),
        compress=_compress_of(body.get(_COMPRESS)),
    )


def _persist_paths_of(raw: object) -> tuple[str, ...]:
    """The paths to persist: relative, sorted, de-duplicated."""
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise ConfigurationError(
            f"{_PERSIST}.{_PATHS} must be a list of paths below the filesystem root, "
            f"not {type(raw).__name__}"
        )
    paths: set[str] = set()
    for element in raw:
        if not isinstance(element, str) or not element:
            raise ConfigurationError(
                f"{_PERSIST}.{_PATHS} contains {element!r}, which is not a path"
            )
        if element.startswith("/"):
            raise ConfigurationError(
                f"{_PERSIST}.{_PATHS} contains the absolute path {element!r}; persisted state "
                f"is relative to the configured root, because that is where it is restored"
            )
        paths.add(element)
    # Sorted so that two documents differing only in the order or the repetition of their paths
    # persist the same tree, which is the same equality the port set is normalised for. Sorting
    # also happens to put a parent before its children, which is the member order a `tar` stream
    # wants; `runtime.persist` does not rely on that, but it does not fight it either.
    return tuple(sorted(paths))


def _persist_deadline_of(raw: object) -> int:
    if raw is None:
        return DEFAULT_PERSIST_DEADLINE_MS
    if isinstance(raw, bool) or not isinstance(raw, int) or raw < 1:
        raise ConfigurationError(
            f"{_PERSIST}.{_DEADLINE_MS} must be a positive number of milliseconds, not {raw!r}"
        )
    if raw > MAX_PERSIST_DEADLINE_MS:
        raise ConfigurationError(
            f"{_PERSIST}.{_DEADLINE_MS} is {raw}, which exceeds the {MAX_PERSIST_DEADLINE_MS} "
            f"this runtime will hold a terminating Sandbox allocated for"
        )
    return raw


def _compress_of(raw: object) -> bool:
    if raw is None:
        return False
    if not isinstance(raw, bool):
        raise ConfigurationError(
            f"{_PERSIST}.{_COMPRESS} must be true or false, not {raw!r}"
        )
    return raw
