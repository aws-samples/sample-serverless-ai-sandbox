# kiro-classification: public
"""The sole issuer of a Session connection credential (R6.2, R11.4, R11.5).

Family A of the design's two credential families — client to Sandbox endpoint — is minted here and
nowhere else. This module is a security boundary, so it is worth stating exactly what the claim is,
what enforces it, and what it does not cover.

## The claim

The permission to mint an endpoint token for a MicroVM is held **only** by the Control_Plane
execution role. No Tenant principal and no Sandbox execution role holds it. That single IAM fact is
what makes the Control_Plane the sole issuer, and it is why R11.4's scoping claim is enforceable
rather than advisory: a caller cannot mint a broader credential than the one it was handed, because
it cannot mint one at all. :mod:`runtime.ports` depends on precisely this — it refuses
`port.expose` for an undeclared port because no credential in existence can be scoped to it, and it
offers no operation that widens the set, since "a runtime that could would be a runtime that could
grant itself reach".

## What makes this module the *one* issuer rather than one of two

:meth:`ConnectionIssuer.issue` is the entry point, and it takes **one argument: the Session
record**. That signature is the load-bearing part. There is no `ports` parameter and no
`ttl_seconds` parameter for a caller to pass, so a caller cannot widen the port set or extend the
lifetime of a credential — not because it is asked not to, but because the call admits no argument
through which it could. Both values are derived here from stored Session state that the caller does
not author, reached through the tenant-confined read path, so a cross-tenant Session identifier
cannot reach the mint at all.

The two derivations are deliberately **not** exported. A public `credential_port_set` helper would
be an invitation for a second call site to compute a port set and hand it to a mint, which is the
shape of "one issuer" decaying into "one helper and several issuers". The only way to obtain a
credential is to ask this class for one.

`ci/lint_rules/sole_credential_issuer.py` keeps the last hole shut: it fails the build if any module
outside this one calls `issue_connection`. Same posture as the Tenant partition key rule — a
structural claim that would otherwise decay silently is checked rather than documented.

## The scoping rules, fixed by the design

- **One Sandbox.** The handle comes from `record.sandbox_handle`, the one Sandbox belonging to the
  one Session, so a credential names exactly one Sandbox identifier (R11.4).
- **The port set** is the Session's declared `exposed_ports` together with
  :data:`SANDBOX_PROTOCOL_CONTROL_PORT`, deduplicated and sorted. A Session that declared no
  exposed ports therefore gets a credential scoped to the control port alone, which is the case
  `runtime.ports` documents from the other side.
- **The lifetime** is `min(configured_credential_ttl, seconds_remaining_in_session)` (R11.5). The
  clamp is not a nicety. A credential outliving its Session is a credential for a Sandbox that may
  already have been reaped and whose identifier may have been reused, so clamping bounds a leaked
  credential's blast radius by a Session that is being torn down anyway. When the remainder is not
  positive there is no lifetime a credential could carry, and :class:`ConnectionNotIssuable` is
  raised rather than a zero-second or negative TTL being sent to a mint.

## What is checked on the way back

The minted descriptor is verified against what was asked for: the port set must be exactly the one
requested and the expiry must not exceed the requested deadline. The mint is trusted code on the
Control_Plane side of the boundary, so this is belt-and-braces rather than the boundary — but a
provider bug that widened a port set or ignored a TTL would otherwise hand out a credential broader
than the Session permits, and R11.4 is a claim about the credential rather than about the intent
behind it.

## The seam, and what phase 12 supplies

:class:`ConnectionMint` is the mechanism seam, in the shape :class:`~runtime.ports.PortRouting`
established: one method, and nothing else passes between the policy that decides scope and the
backend that mints. :class:`~control_plane.providers.base.ComputeProvider` satisfies it
structurally, so :class:`RegisteredProviderMint` is the whole of the deployment wiring — it selects
the provider from the handle, which already carries the provider name. No endpoint URL, no signing
key and no token format appears anywhere in this module: every one of those is data on the
descriptor the mint returns, which is what keeps the endpoint authentication scheme inside the
Compute_Provider seam (R5.6). Nothing here makes an AWS call at import time and the mint is
injected, so the offline suite drives every path with no deployed resource and no network.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final, Protocol

from control_plane.providers.base import ConnectionDescriptor as MintedConnection
from control_plane.providers.base import SandboxHandle
from control_plane.state.keys import ItemShapeError
from control_plane.state.records import ConnectionDescriptor, SessionRecord

__all__ = [
    "DEFAULT_CREDENTIAL_TTL_SECONDS",
    "SANDBOX_PROTOCOL_CONTROL_PORT",
    "ConnectionIssuer",
    "ConnectionMint",
    "ConnectionNotIssuable",
    "CredentialPolicy",
    "RegisteredProviderMint",
]

#: The Sandbox_Protocol control port, which every issued credential is scoped to whatever the
#: Session declared. It is the port `runtime.server` binds, and the number is part of the
#: deployment's contract rather than a local preference on either side; the offline suite asserts
#: the two spellings agree, because a credential scoped to a port the runtime does not serve would
#: be a credential that authenticates against nothing.
SANDBOX_PROTOCOL_CONTROL_PORT: Final = 8000

#: The configured credential lifetime before the Session remainder clamps it. 900 s is the design's
#: default: long enough that a client is not refreshing constantly, short enough that a leaked
#: credential is a fifteen-minute problem rather than an eight-hour one.
DEFAULT_CREDENTIAL_TTL_SECONDS: Final = 900

_MILLISECONDS_PER_SECOND: Final = 1000


class ConnectionNotIssuable(Exception):
    """No credential can be issued for this Session, and the reason is a property of the Session.

    Distinct from a failure of the mint. This is raised when the Session itself admits no
    credential — it is terminal, it has no Sandbox yet, or its maximum duration has elapsed — so
    the caller's correct response is to report the state rather than to retry the mint.
    """

    def __init__(self, session_id: str, reason: str) -> None:
        super().__init__(f"no connection credential can be issued: {reason}")
        self.session_id = session_id
        self.reason = reason


class ConnectionMint(Protocol):
    """The backend operation whose IAM permission the Control_Plane execution role alone holds.

    A Protocol with one method, because that is the entire dependency: this module decides the
    scope and the lifetime, and the backend mints a credential carrying them.
    :class:`~control_plane.providers.base.ComputeProvider` satisfies it structurally, so no
    provider implements an interface that exists for this module's convenience.
    """

    def issue_connection(
        self, handle: SandboxHandle, ports: tuple[int, ...], ttl_seconds: int
    ) -> MintedConnection:
        """Mint a Sandbox-scoped, port-scoped connection credential that expires."""
        ...


@dataclass(frozen=True, slots=True)
class RegisteredProviderMint:
    """The deployment's mint: the registered provider the Sandbox handle names.

    Selection is by `handle.provider_name` rather than by a constructor argument, so one issuer
    serves a deployment with more than one registered provider without a second issuer existing
    and without the scoping decisions being made twice.
    """

    def issue_connection(
        self, handle: SandboxHandle, ports: tuple[int, ...], ttl_seconds: int
    ) -> MintedConnection:
        """Delegate to the registered provider that owns this Sandbox."""
        # Imported here rather than at module scope so that importing the issuer does not import
        # every registered provider, and with them boto3, into a test that only needs the policy.
        from control_plane.providers import registry

        return registry.get(handle.provider_name).issue_connection(
            handle, ports, ttl_seconds
        )


@dataclass(frozen=True, slots=True)
class CredentialPolicy:
    """The two deployment-configured numbers credential scoping depends on.

    Both are configuration rather than request content, which is the point: a caller influences
    neither. The control port is a field rather than a constant read directly so that a deployment
    whose runtime binds elsewhere configures one value in one place, and so a test can state a
    deployment without monkeypatching a module constant.
    """

    ttl_seconds: int = DEFAULT_CREDENTIAL_TTL_SECONDS
    control_port: int = SANDBOX_PROTOCOL_CONTROL_PORT

    def __post_init__(self) -> None:
        if self.ttl_seconds <= 0:
            raise ValueError(
                f"ttl_seconds must be greater than zero: {self.ttl_seconds}"
            )
        if not 1 <= self.control_port <= 65535:
            raise ValueError(f"control_port is not a port: {self.control_port}")


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _epoch_milliseconds(moment: datetime) -> int:
    """Epoch milliseconds for an aware instant, matching the record's own time unit."""
    if moment.tzinfo is None:
        # A naive clock compared against a stored epoch would silently assume a timezone, and a
        # credential lifetime is not a thing to guess at.
        raise ValueError("the issuer's clock must return an aware datetime")
    return int(moment.timestamp() * _MILLISECONDS_PER_SECOND)


def _iso_z(moment: datetime) -> str:
    """Render an expiry as the `2026-06-22T10:15:00Z` form the connection descriptor carries.

    Sub-second precision is truncated, which moves the stated expiry earlier than the real one by
    under a second. That is the safe direction: a client refreshes marginally early rather than
    presenting a credential it believes is still valid.
    """
    return (
        moment.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    )


def _handle_of(record: SessionRecord) -> SandboxHandle:
    """Rebuild the provider handle stored on the Session row.

    A malformed handle is **not** absorbed into :class:`ConnectionNotIssuable`. An item in the
    caller's own partition with the wrong shape is a defect in this system rather than a statement
    about the Session, and reporting it as "no credential is available" would hide a bug behind a
    lifecycle answer — the same distinction :mod:`control_plane.api.lookup` draws.
    """
    stored = record.sandbox_handle
    if stored is None:  # pragma: no cover - guarded by the caller
        raise ItemShapeError("sandboxHandle is absent")
    provider_name = stored.get("providerName")
    sandbox_id = stored.get("sandboxId")
    if not isinstance(provider_name, str) or not provider_name:
        raise ItemShapeError("sandboxHandle carries no providerName")
    if not isinstance(sandbox_id, str) or not sandbox_id:
        raise ItemShapeError("sandboxHandle carries no sandboxId")
    opaque = stored.get("opaque", {})
    if not isinstance(opaque, Mapping):
        raise ItemShapeError("sandboxHandle opaque data is not a map")
    return SandboxHandle(
        provider_name=provider_name,
        sandbox_id=sandbox_id,
        opaque={str(key): str(value) for key, value in opaque.items()},
    )


@dataclass(frozen=True, slots=True)
class ConnectionIssuer:
    """The one path by which a Session connection credential comes into existence.

    Construct it with a mint and, where a deployment configures them, a policy and a clock. Then
    call :meth:`issue`. There is no other public operation and no module-level shortcut.
    """

    mint: ConnectionMint = RegisteredProviderMint()
    policy: CredentialPolicy = CredentialPolicy()
    clock: Callable[[], datetime] = _utc_now

    def issue(self, record: SessionRecord) -> ConnectionDescriptor:
        """Mint a credential for this Session, scoped and clamped to what the record permits.

        The record is the only argument. Everything a credential's reach depends on — which
        Sandbox, which ports, how long — is read from it, so there is no parameter through which a
        caller could widen any of the three.

        Returns the descriptor in the form the Session row stores and the API returns, so a
        published credential and a returned one are the same value rather than two renderings of
        one (R6.13).

        Raises:
            ConnectionNotIssuable: the Session is terminal, has no Sandbox, or has run out of
                remaining duration, so no credential can be scoped to it.
            ItemShapeError: the stored Sandbox handle is malformed, which is a defect rather than
                an answer about the Session.
        """
        handle = self._handle_for(record)
        ports = self._port_set(record)
        ttl_seconds = self._ttl_seconds(record)

        minted = self.mint.issue_connection(handle, ports, ttl_seconds)
        self._verify(record, minted, ports, ttl_seconds)
        return ConnectionDescriptor(
            base_url=minted.base_url,
            auth_header_name=minted.auth_header_name,
            auth_header_value=minted.auth_header_value,
            ports=tuple(minted.ports),
            expires_at=_iso_z(minted.expires_at),
        )

    # -- the three derivations, none of them reachable from outside -------------------------

    def _handle_for(self, record: SessionRecord) -> SandboxHandle:
        if record.lifecycle_state.is_terminal:  # nosemgrep: is-function-without-parentheses — @property
            raise ConnectionNotIssuable(
                record.session_id,
                f"the Session is {record.lifecycle_state.value}",
            )
        if record.sandbox_handle is None:
            raise ConnectionNotIssuable(
                record.session_id,
                f"no Sandbox is provisioned for this Session yet "
                f"(lifecycle state {record.lifecycle_state.value})",
            )
        return _handle_of(record)

    def _port_set(self, record: SessionRecord) -> tuple[int, ...]:
        """The declared exposed ports together with the control port, deduplicated and sorted.

        Sorted so that two credentials for one Session are comparable, and deduplicated because a
        Session may legally declare the control port itself and a repeated port in a scope list
        says nothing the single entry does not.
        """
        return tuple(sorted({*record.exposed_ports, self.policy.control_port}))

    def _ttl_seconds(self, record: SessionRecord) -> int:
        """`min(configured lifetime, Session remainder)`, in whole seconds.

        The remainder is floored rather than rounded, so the clamp can only ever shorten a
        credential relative to the Session deadline and never carry it a fraction of a second past.
        """
        per_second = _MILLISECONDS_PER_SECOND
        deadline_ms = record.created_at + record.max_duration_seconds * per_second
        remaining = (deadline_ms - _epoch_milliseconds(self.clock())) // per_second
        if remaining <= 0:
            raise ConnectionNotIssuable(
                record.session_id,
                "the Session's maximum duration has elapsed, so no credential could outlast it",
            )
        return min(self.policy.ttl_seconds, remaining)

    def _verify(
        self,
        record: SessionRecord,
        minted: MintedConnection,
        ports: tuple[int, ...],
        ttl_seconds: int,
    ) -> None:
        """Refuse a minted credential broader than the one that was asked for.

        R11.4 and R11.5 are claims about the credential a caller receives, so they are checked on
        what came back rather than assumed from what went out.
        """
        if tuple(sorted(set(minted.ports))) != ports:
            raise ConnectionNotIssuable(
                record.session_id,
                f"the mint returned a credential scoped to {sorted(set(minted.ports))} "
                f"rather than to {list(ports)}",
            )
        latest = self.clock() + timedelta(seconds=ttl_seconds)
        if minted.expires_at.tzinfo is None:
            raise ConnectionNotIssuable(
                record.session_id, "the mint returned an expiry with no timezone"
            )
        if minted.expires_at > latest:
            raise ConnectionNotIssuable(
                record.session_id,
                f"the mint returned an expiry at {minted.expires_at.isoformat()}, "
                f"beyond the {ttl_seconds} s this Session permits",
            )
