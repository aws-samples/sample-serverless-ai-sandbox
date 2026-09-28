# kiro-classification: public
"""Property 15: connection credential scoping and expiry (R6.2, R11.4, R11.5).

Three claims over one drawn Session each time: the credential names exactly one Sandbox, its port
set is the declared ports together with the control port and no others, and its expiry is the
minimum of the configured credential lifetime and the Session's remaining duration.
`test_connection_credentials.py` pins the examples underneath this — a Session declaring nothing, a
Session declaring two ports, one remainder above the configured lifetime and one below. What is
generalised here is the *domain*, and the domain is chosen so that each of the three claims can
fail independently.

## What is drawn, and why each dimension is there

| Dimension | Reaches |
| --- | --- |
| declared port sets: empty, singletons, duplicates, the control port itself, ports 1 and 65535 | the deduplication, the sort, and the "control port alone" case (R11.4) |
| the configured control port | that the union is taken against the *policy's* port rather than a constant read behind it |
| the configured credential lifetime | both directions of the clamp (R11.5) |
| the Session's maximum duration and the elapsed time, anchored on the deadline | that the clamp uses the *remainder* rather than the whole duration |
| sub-second and exhausted remainders | the floor, and the refusal where no positive lifetime is left |
| the Sandbox identifier on the stored handle | that the credential names that Sandbox and no other (R6.2) |
| a mint that widens, narrows, permutes or overshoots | that R11.4 and R11.5 are checked on the credential that came back |

The elapsed time is drawn **relative to the Session deadline** rather than uniformly, because a
uniform draw over an eight-hour Session almost never lands on the second where the remainder equals
the configured lifetime, and that second is the boundary the clamp turns on. The anchors put the
clock exactly on it, one microsecond either side of it, exactly on the deadline, one microsecond
short of it, and one whole second short of it — the last two being the cases where an
implementation that rounded rather than floored would carry a credential a fraction of a second
past the Session it belongs to.

## The mint misbehaviour arm, and how the property is phrased to include it

R11.4 and R11.5 are claims about the credential a caller *receives*, so a mint that widened the
port set or overshot the expiry must not produce one. The property is therefore a disjunction:
either a credential comes back and it carries exactly the derived scope and expiry, or no
credential comes back at all. A property that only drove a faithful mint would pass against an
issuer that had deleted its own verification, which is the failure this arm exists to catch.

A mint that returns the *same set* in a different order, or with a repeated entry, is accepted —
the claim is set equality, which is why the returned descriptor is asserted as a set. It is worth
recording that the descriptor then carries the mint's ordering rather than the issuer's sorted
tuple, since :meth:`ConnectionIssuer.issue` passes `tuple(minted.ports)` through. That is within
R11.4, which is about reach rather than about presentation, so it is noted here rather than
asserted against.

## Why the mint double is imported rather than redefined

`ci/lint_rules/sole_credential_issuer.py` rejects a *definition* of `issue_connection` outside the
provider seam as firmly as it rejects a call to one, and it is right to: a second implementation of
the mint is a second issuer with extra steps. So this module imports `RecordingMint` from
`test_connection_credentials.py`, which the rule's allow-list already carries, rather than adding
an entry to that allow-list for a double this suite already has. Nothing here calls the mint; the
only way a credential comes into existence in this file is
:meth:`ConnectionIssuer.issue`.

## Non-vacuity

Two deterministic tests follow the property, neither drawing anything. The first runs the same
checker over an enumerated case for every bucket the generator can produce, and asserts that the
buckets are all reached and that all four outcomes are driven, so no arm of the checker is dead.
The second asserts that three plausible wrong derivations — a port set without the control port, a
clamp against the whole configured duration rather than the remainder, and an issuer that accepted
a widened credential — each disagree with what the issuer actually does. An assertion that no wrong
implementation could fail is an assertion that proves nothing.

## Budget

500 examples rather than the design's floor of 100. Every example is integer arithmetic over an
in-memory record with an injected clock and an injected mint: no subprocess, no filesystem, no
network, and no wall-clock wait, so the whole property runs in well under a second. The ten drawn
dimensions multiply out far past 100 combinations, so the floor would leave whole buckets unvisited
on most runs; at 500 every one of the sixteen is observed, the rarest at around 8% of examples.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Final

import pytest
from hypothesis import event, given, settings
from hypothesis import strategies as st

from control_plane.credentials import (
    SANDBOX_PROTOCOL_CONTROL_PORT,
    ConnectionIssuer,
    ConnectionNotIssuable,
    CredentialPolicy,
)
from control_plane.state.records import LifecycleState, SessionRecord
from tests.test_connection_credentials import (
    CREATED_AT_MS,
    FAKE_TOKEN,
    NOW,
    RecordingMint,
    session_record,
)

#: The provider name on the stored handle. Fixed, so the record's `providerName` and its handle's
#: agree; what is drawn is the Sandbox identifier, which is what "names exactly one Sandbox" means.
PROVIDER_NAME: Final = "local-firecracker"

#: The service ceiling on a Session duration (R6.5), so no drawn Session is one the Control_Plane
#: would have refused to create.
MAX_SESSION_DURATION_SECONDS: Final = 28_800

#: The lowest and highest port numbers, which `SessionRecord` accepts and nothing between the
#: issuer and the mint may treat specially.
LOWEST_PORT: Final = 1
HIGHEST_PORT: Final = 65535

#: Ports worth drawing by name: both ends of the range, the control port itself, and a few ordinary
#: ones. Uniform draws over the whole range are mixed in as well, but a uniform draw alone would
#: essentially never produce the case where a Session declares the control port.
PORT_POOL: Final = (
    LOWEST_PORT,
    22,
    80,
    3000,
    SANDBOX_PROTOCOL_CONTROL_PORT,
    8080,
    9000,
    HIGHEST_PORT,
)

#: Control ports a deployment might configure. `CredentialPolicy` takes the port as a field
#: precisely so that a deployment whose runtime binds elsewhere configures one value in one place,
#: so the union is drawn against more than the default.
CONTROL_PORT_POOL: Final = (
    SANDBOX_PROTOCOL_CONTROL_PORT,
    LOWEST_PORT,
    8080,
    HIGHEST_PORT,
)

#: Configured credential lifetimes, including one so short that every Session remainder exceeds it
#: and one so long that every remainder clamps it.
TTL_POOL: Final = (1, 60, 300, 900, 3600, MAX_SESSION_DURATION_SECONDS)

#: Session durations worth naming, including the one-second Session whose credential expires almost
#: immediately and the eight-hour ceiling.
DURATION_POOL: Final = (1, 2, 120, 900, 3600, MAX_SESSION_DURATION_SECONDS)

#: A Session may declare no ports at all; the upper bound is this generator's rather than the
#: record's, which imposes none. Twelve is past the point where a further port reaches anything new.
MAX_DECLARED_PORTS: Final = 12

_MICROSECONDS_PER_SECOND: Final = 1_000_000
_MILLISECONDS_PER_SECOND: Final = 1_000

# The four outcomes the property distinguishes, named so the assertions read as the claim rather
# than as a chain of conditions.
ISSUED: Final = "issued"
EXHAUSTED: Final = "no-lifetime-remains"
REFUSED_SCOPE: Final = "refused-a-mismatched-port-set"
REFUSED_EXPIRY: Final = "refused-an-overshot-expiry"

# What the mint does with what it was asked for.
HONEST: Final = "honest"
WIDENED: Final = "widened"
NARROWED: Final = "narrowed"
PERMUTED: Final = "permuted"

#: Every bucket the generator can land in. The enumerated-case test asserts each is reachable, so a
#: generator that quietly stopped producing one would be caught rather than silently shrink the
#: domain the property covers.
BUCKETS: Final = frozenset(
    {
        "declared: none",
        "declared: one",
        "declared: several",
        "declared: repeated entry",
        "declared: includes the control port",
        "declared: a range boundary",
        "remainder: above the configured lifetime",
        "remainder: equal to the configured lifetime",
        "remainder: below the configured lifetime",
        "remainder: sub-second, floored away",
        "remainder: exhausted",
        f"mint: {HONEST}",
        f"mint: {WIDENED}",
        f"mint: {NARROWED}",
        f"mint: {PERMUTED}",
        "mint: overshot the expiry",
    }
)


@dataclass(frozen=True, slots=True)
class IssuanceCase:
    """One drawn Session, one drawn deployment configuration, and one drawn mint behaviour.

    Everything the property expects is derived here, by arithmetic the issuer does not share, so
    the expectations are an independent statement of R11.4 and R11.5 rather than a second call into
    the code under test.
    """

    declared_ports: tuple[int, ...]
    control_port: int
    configured_ttl_seconds: int
    max_duration_seconds: int
    elapsed_microseconds: int
    sandbox_id: str
    lifecycle_state: LifecycleState
    mint_mode: str
    widening_port: int
    overshoot: timedelta

    @property
    def now(self) -> datetime:
        """The instant the injected clock reports. Never the wall clock."""
        return NOW + timedelta(microseconds=self.elapsed_microseconds)

    @property
    def session_deadline(self) -> datetime:
        """`created_at + max_duration`: the instant no credential may outlive."""
        return NOW + timedelta(seconds=self.max_duration_seconds)

    @property
    def expected_ports(self) -> tuple[int, ...]:
        """R11.4: the declared ports together with the control port, deduplicated and sorted."""
        return tuple(sorted({*self.declared_ports, self.control_port}))

    @property
    def remaining_seconds(self) -> int:
        """Whole seconds left of the Session, floored, against the injected clock."""
        deadline_ms = (
            CREATED_AT_MS + self.max_duration_seconds * _MILLISECONDS_PER_SECOND
        )
        now_ms = CREATED_AT_MS + self.elapsed_microseconds // _MILLISECONDS_PER_SECOND
        return (deadline_ms - now_ms) // _MILLISECONDS_PER_SECOND

    @property
    def expected_ttl_seconds(self) -> int:
        """R11.5: the configured lifetime, clamped by what is left of the Session."""
        return min(self.configured_ttl_seconds, self.remaining_seconds)

    @property
    def minted_ports(self) -> tuple[int, ...] | None:
        """What the mint returns, or None where it returns exactly what it was asked for."""
        if self.mint_mode == HONEST:
            return None
        if self.mint_mode == WIDENED:
            return (*self.expected_ports, self.widening_port)
        if self.mint_mode == NARROWED:
            return self.expected_ports[:-1]
        # Permuted: the same set, reversed, with a repeated entry. Set-equal, so it is accepted.
        return (*reversed(self.expected_ports), self.expected_ports[0])

    @property
    def expected_outcome(self) -> str:
        """Which of the four outcomes this case must produce, in the order the issuer decides."""
        if self.remaining_seconds <= 0:
            return EXHAUSTED
        if self.mint_mode in {WIDENED, NARROWED}:
            return REFUSED_SCOPE
        if self.overshoot > timedelta():
            return REFUSED_EXPIRY
        return ISSUED

    def buckets(self) -> frozenset[str]:
        """The buckets this case occupies, for `event()` and for the non-vacuity check."""
        declared = set(self.declared_ports)
        found = {f"mint: {self.mint_mode}"}
        if not declared:
            found.add("declared: none")
        elif len(declared) == 1:
            found.add("declared: one")
        else:
            found.add("declared: several")
        if len(self.declared_ports) != len(declared):
            found.add("declared: repeated entry")
        if self.control_port in declared:
            found.add("declared: includes the control port")
        if declared & {LOWEST_PORT, HIGHEST_PORT}:
            found.add("declared: a range boundary")
        remaining = self.remaining_seconds
        if remaining <= 0:
            found.add("remainder: exhausted")
            if self.now < self.session_deadline:
                # Under a second of the Session left, floored away rather than rounded up.
                found.add("remainder: sub-second, floored away")
        elif remaining > self.configured_ttl_seconds:
            found.add("remainder: above the configured lifetime")
        elif remaining == self.configured_ttl_seconds:
            found.add("remainder: equal to the configured lifetime")
        else:
            found.add("remainder: below the configured lifetime")
        if self.overshoot > timedelta():
            found.add("mint: overshot the expiry")
        return frozenset(found)


@st.composite
def port_set(drawn: st.DrawFn) -> tuple[int, ...]:
    """Declared port sets: empty, singletons, duplicates, boundaries, and the control port.

    Ports come from a named pool mixed with uniform draws over the whole range, and one entry is
    sometimes repeated so the deduplication is exercised rather than assumed.
    """
    port = st.one_of(
        st.sampled_from(PORT_POOL),
        st.integers(min_value=LOWEST_PORT, max_value=HIGHEST_PORT),
    )
    ports = drawn(st.lists(port, min_size=0, max_size=MAX_DECLARED_PORTS))
    repeat_one = drawn(st.booleans())
    if ports and repeat_one:
        ports.append(drawn(st.sampled_from(ports)))
    return tuple(ports)


def elapsed(max_duration_seconds: int, ttl_seconds: int) -> st.SearchStrategy[int]:
    """Microseconds since `created_at`, anchored on the instants the clamp turns on.

    A uniform draw over an eight-hour Session would land on neither the second where the remainder
    equals the configured lifetime nor the microsecond before the deadline, so both are named.
    """
    duration = max_duration_seconds * _MICROSECONDS_PER_SECOND
    boundary = duration - ttl_seconds * _MICROSECONDS_PER_SECOND
    anchors = (
        0,
        boundary,
        boundary - 1,
        boundary + 1,
        duration - _MICROSECONDS_PER_SECOND,
        duration - _MICROSECONDS_PER_SECOND - 1,
        duration - _MICROSECONDS_PER_SECOND // 2,
        duration - 1,
        duration,
        duration + 1,
        duration + _MICROSECONDS_PER_SECOND,
    )
    return st.one_of(
        st.sampled_from([anchor for anchor in anchors if anchor >= 0]),
        st.integers(min_value=0, max_value=duration + _MICROSECONDS_PER_SECOND),
    )


def port_outside_the_scope(scoped: set[int], candidate: int) -> int:
    """The first port at or after `candidate`, wrapping, that a credential is not scoped to.

    A `filter` on the draw would abort examples instead: Hypothesis prefers small integers and the
    scoped set frequently contains port 1. `scoped` holds at most `MAX_DECLARED_PORTS + 1` members,
    so the search terminates well inside the port range on every input.
    """
    span = HIGHEST_PORT - LOWEST_PORT + 1
    for offset in range(span):
        port = (candidate - LOWEST_PORT + offset) % span + LOWEST_PORT
        if port not in scoped:
            return port
    raise AssertionError(  # pragma: no cover - 65535 ports and at most 13 are scoped
        "every port is scoped, which the size of the port range makes impossible"
    )


@st.composite
def issuance_case(drawn: st.DrawFn) -> IssuanceCase:
    """One Session, one deployment configuration, and one mint behaviour."""
    declared_ports = drawn(port_set())
    control_port = drawn(st.sampled_from(CONTROL_PORT_POOL))
    configured_ttl_seconds = drawn(
        st.one_of(
            st.sampled_from(TTL_POOL),
            st.integers(min_value=1, max_value=MAX_SESSION_DURATION_SECONDS),
        )
    )
    max_duration_seconds = drawn(
        st.one_of(
            st.sampled_from(DURATION_POOL),
            st.integers(min_value=1, max_value=MAX_SESSION_DURATION_SECONDS),
        )
    )
    scoped = {*declared_ports, control_port}
    return IssuanceCase(
        declared_ports=declared_ports,
        control_port=control_port,
        configured_ttl_seconds=configured_ttl_seconds,
        max_duration_seconds=max_duration_seconds,
        elapsed_microseconds=drawn(
            elapsed(max_duration_seconds, configured_ttl_seconds)
        ),
        sandbox_id=drawn(
            st.text(
                alphabet=st.characters(min_codepoint=97, max_codepoint=122),
                min_size=1,
                max_size=16,
            )
        ),
        # Terminal states admit no credential for a reason that is not about scope, and
        # `test_connection_credentials.py` pins them. Every state drawn here reaches the mint.
        lifecycle_state=drawn(
            st.sampled_from([state for state in LifecycleState if not state.is_terminal])
        ),
        # Honest twice, so the arm that returns a credential is drawn about as often as the three
        # misbehaviours together.
        mint_mode=drawn(
            st.sampled_from((HONEST, HONEST, HONEST, WIDENED, NARROWED, PERMUTED))
        ),
        widening_port=port_outside_the_scope(
            scoped, drawn(st.integers(min_value=LOWEST_PORT, max_value=HIGHEST_PORT))
        ),
        overshoot=drawn(
            st.sampled_from(
                (
                    timedelta(),
                    timedelta(),
                    timedelta(),
                    timedelta(microseconds=1),
                    timedelta(seconds=1),
                    timedelta(seconds=MAX_SESSION_DURATION_SECONDS),
                )
            )
        ),
    )


def record_for(case: IssuanceCase) -> SessionRecord:
    """The Session row, built through `pk_for` by the shared helper, carrying the drawn handle."""
    return session_record(
        exposed_ports=case.declared_ports,
        lifecycle_state=case.lifecycle_state,
        max_duration_seconds=case.max_duration_seconds,
        sandbox_handle={
            "providerName": PROVIDER_NAME,
            "sandboxId": case.sandbox_id,
            "opaque": {},
        },
    )


def issuer_for(case: IssuanceCase, mint: RecordingMint) -> ConnectionIssuer:
    """The issuer under this deployment's configuration, on an injected clock."""
    return ConnectionIssuer(
        mint=mint,
        policy=CredentialPolicy(
            ttl_seconds=case.configured_ttl_seconds, control_port=case.control_port
        ),
        clock=lambda: case.now,
    )


def mint_for(case: IssuanceCase) -> RecordingMint:
    """The recording double, told how to misbehave where this case says it should."""
    return RecordingMint(
        now=case.now,
        override_ports=case.minted_ports,
        expiry_overshoot=case.overshoot,
    )


def expected_expiry(case: IssuanceCase) -> str:
    """The `2026-06-22T10:15:00Z` rendering of `now + clamped lifetime`, truncated downwards."""
    moment = case.now + timedelta(seconds=case.expected_ttl_seconds)
    return moment.astimezone(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def check_case(case: IssuanceCase) -> str:
    """Assert the property against one case and return the outcome that was observed.

    Returned rather than only asserted, so the enumerated-case test can state which arm it drove.
    """
    mint = mint_for(case)
    outcome = case.expected_outcome

    if outcome != ISSUED:
        with pytest.raises(ConnectionNotIssuable) as raised:
            issuer_for(case, mint).issue(record_for(case))
        if outcome == EXHAUSTED:
            # No positive lifetime exists, so nothing is asked of the mint at all: a zero or
            # negative TTL must not reach it.
            assert "maximum duration has elapsed" in raised.value.reason
            assert mint.calls == []
        elif outcome == REFUSED_SCOPE:
            assert "rather than to" in raised.value.reason
            assert mint.calls[0][1] == case.expected_ports
        else:
            assert "beyond the" in raised.value.reason
            assert mint.calls[0][2] == case.expected_ttl_seconds
        return outcome

    connection = issuer_for(case, mint).issue(record_for(case))

    # R6.2: exactly one Sandbox is named, and it is the one on the stored handle.
    assert len(mint.calls) == 1
    handle, requested_ports, requested_ttl = mint.calls[0]
    assert handle.sandbox_id == case.sandbox_id
    assert handle.provider_name == PROVIDER_NAME

    # R11.4: the declared ports together with the control port and no others -- asserted on the
    # credential that came back, which is what `runtime.ports` relies on when it refuses to expose
    # a port the Session never declared.
    assert requested_ports == case.expected_ports
    assert set(connection.ports) == set(case.expected_ports)
    assert not set(connection.ports) - {*case.declared_ports, case.control_port}
    assert case.control_port in set(connection.ports)

    # R11.5: the configured lifetime clamped by the Session remainder, and never past the deadline.
    assert requested_ttl == case.expected_ttl_seconds
    assert requested_ttl <= case.configured_ttl_seconds
    assert requested_ttl <= case.remaining_seconds
    assert requested_ttl >= 1
    assert connection.expires_at == expected_expiry(case)
    expires_at = datetime.fromisoformat(connection.expires_at)
    assert expires_at <= case.now + timedelta(seconds=requested_ttl)
    assert expires_at > case.now + timedelta(seconds=requested_ttl - 1)
    assert expires_at <= case.session_deadline

    # A credential was actually produced, rather than the assertions above holding of nothing.
    assert connection.auth_header_value == FAKE_TOKEN
    return outcome


# Feature: aws-serverless-agent-sandbox, Property 15: For all Sessions and their declared port
# sets, the issued connection credential names exactly one Sandbox identifier and a port set equal
# to the declared ports together with the control port and no others, and its expiry equals the
# minimum of the configured credential lifetime and the Session's remaining duration.
@given(case=issuance_case())
@settings(max_examples=500)
def test_a_credential_names_one_sandbox_its_ports_and_expires_with_the_session(
    case: IssuanceCase,
) -> None:
    """**Validates: Requirements 6.2, 11.4, 11.5**"""
    for bucket in case.buckets():
        event(bucket)
    assert check_case(case) == case.expected_outcome


# --- Non-vacuity, both deterministic ------------------------------------------------------

#: The case every enumerated one below varies from: two declared ports, the default control port,
#: the default lifetime, a Session with an hour on it, and a mint that does as it is told.
BASE_CASE: Final = IssuanceCase(
    declared_ports=(3000, 8080),
    control_port=SANDBOX_PROTOCOL_CONTROL_PORT,
    configured_ttl_seconds=900,
    max_duration_seconds=3600,
    elapsed_microseconds=0,
    sandbox_id="sandbox-1",
    lifecycle_state=LifecycleState.RUNNING,
    mint_mode=HONEST,
    widening_port=9001,
    overshoot=timedelta(),
)

#: One case per bucket, stated rather than drawn, so every arm of the checker is exercised whatever
#: the generator happens to produce on a given run.
ENUMERATED_CASES: Final = (
    replace(BASE_CASE, declared_ports=()),
    replace(BASE_CASE, declared_ports=(8080,)),
    replace(BASE_CASE, declared_ports=(3000, 8080, 9000)),
    replace(BASE_CASE, declared_ports=(8080, 8080)),
    replace(BASE_CASE, declared_ports=(SANDBOX_PROTOCOL_CONTROL_PORT, 3000)),
    replace(BASE_CASE, declared_ports=(LOWEST_PORT, HIGHEST_PORT)),
    # The remainder in each relation to the configured lifetime: 3600 s > 900 s, 900 s == 900 s,
    # 120 s < 900 s, half a second floored to none, and the deadline itself.
    replace(BASE_CASE, max_duration_seconds=3600),
    replace(BASE_CASE, max_duration_seconds=900),
    replace(BASE_CASE, max_duration_seconds=120),
    replace(BASE_CASE, max_duration_seconds=10, elapsed_microseconds=9_500_000),
    replace(BASE_CASE, max_duration_seconds=10, elapsed_microseconds=10_000_000),
    # The mint's misbehaviour, one arm each.
    replace(BASE_CASE, mint_mode=WIDENED),
    replace(BASE_CASE, mint_mode=NARROWED),
    replace(BASE_CASE, mint_mode=PERMUTED),
    replace(BASE_CASE, overshoot=timedelta(microseconds=1)),
)


def test_every_bucket_is_reachable_and_the_property_holds_on_each() -> None:
    """The domain the property claims to cover is one no arm of which is dead."""
    covered: set[str] = set()
    outcomes: set[str] = set()
    for case in ENUMERATED_CASES:
        outcomes.add(check_case(case))
        covered |= case.buckets()
    assert covered == BUCKETS, f"buckets never reached: {sorted(BUCKETS - covered)}"
    assert outcomes == {ISSUED, EXHAUSTED, REFUSED_SCOPE, REFUSED_EXPIRY}


def test_the_assertions_discriminate_three_plausible_wrong_derivations() -> None:
    """Each wrong rule disagrees with the issuer on a case the property draws.

    Without this, "the credential matches what I computed" could be true of an implementation that
    computed the same wrong thing in both places.
    """
    # 1. A port set that omitted the control port. R11.4's union is not the declared set.
    declared = replace(BASE_CASE, declared_ports=(3000, 8080))
    mint = mint_for(declared)
    connection = issuer_for(declared, mint).issue(record_for(declared))
    assert set(connection.ports) != set(declared.declared_ports)
    assert set(connection.ports) == {3000, SANDBOX_PROTOCOL_CONTROL_PORT, 8080}

    # 2. A clamp against the whole configured duration rather than the remainder: halfway through
    #    a 1,000 s Session, 500 s remain, not 1,000.
    halfway = replace(
        BASE_CASE,
        declared_ports=(),
        max_duration_seconds=1000,
        elapsed_microseconds=500 * _MICROSECONDS_PER_SECOND,
    )
    mint = mint_for(halfway)
    issuer_for(halfway, mint).issue(record_for(halfway))
    assert mint.calls[0][2] == 500
    assert mint.calls[0][2] != min(
        halfway.configured_ttl_seconds, halfway.max_duration_seconds
    )

    # 3. An issuer that trusted the mint: a widened credential must not come back.
    widened = replace(BASE_CASE, declared_ports=(3000,), mint_mode=WIDENED)
    mint = mint_for(widened)
    with pytest.raises(ConnectionNotIssuable):
        issuer_for(widened, mint).issue(record_for(widened))
    assert mint.calls[0][1] == (3000, SANDBOX_PROTOCOL_CONTROL_PORT)
