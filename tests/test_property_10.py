# kiro-classification: public
"""Property 10: per-Session values are unique across Sandboxes from one image version (R7.12).

R7.12 names its own adversary, and the naming is the whole requirement: "so that no such value is
captured during image build and shared across Sandboxes started from one image version". So the
claim under test is not "the values look random" — a property that only measured entropy would
pass against a runtime that drew one excellent 32-byte key while the image was being built and
handed the same one to every Sandbox started from it. The claim is *disjointness between
Sandboxes that share an import*.

## How "from one image version" is expressed here

An image version, to a Python process, is a module object: the code that every Sandbox started
from that image executes is `runtime.session_values` as imported once, at the top of this file.
Every Sandbox in a drawn batch is therefore built from that already-imported module in this one
process — no `importlib.reload`, no subprocess, no second copy of the code. That is a stronger
arrangement than starting separate MicroVMs would be, because a value cached at import is *shared*
between these Sandboxes rather than merely equal across them, so the three ways the design names of
failing R7.12 are all reachable:

* a module-level constant, drawn once when the module was first imported;
* a class attribute, drawn once when the class body executed;
* a default argument, which is the subtlest of the three — Python evaluates it exactly once, at
  import, and the runtime is imported while the image is being built, so a default argument is
  *literally* image content wearing the shape of a per-call value.

`test_a_batch_from_a_cached_implementation_fails_the_property` demonstrates that each of the three
fails the assertion this property makes, rather than asserting that it would. See the non-vacuity
note below.

## Both ways in, and one union to assert on

Half of each batch is started by driving the real ASGI application's `/run` endpoint over a drawn
configuration document and reading the values it published; the other half calls
`SessionValues.generate()` directly. Both halves are needed and for different reasons. R7.12 is a
statement about the values generated *inside the `/run` hook*, so a test that only called the
generator would be asserting about a function the hook might not use, or might call once and cache;
and a test that only went through the hook would be a much slower way to reach the generator with
no additional failure mode covered by the extra distance.

The assertion is then made over the *union* of the two halves rather than over each half
separately, which is strictly stronger and is the honest reading of the claim: a Sandbox that
generated directly and a Sandbox that generated through its `/run` hook were both started from this
one import, so a value shared between them is a value captured at import time just the same. A
module-scope cache is invisible to a within-half comparison if the hook consults it and the direct
call does not, or the reverse.

Disjointness is asserted over every pair drawn from the whole batch (`itertools.combinations`),
not between consecutive elements. Consecutive comparison would pass a generator that alternated
between two cached values, which is a two-value cache and exactly as much of an R7.12 violation as
a one-value cache.

## The second conjunct, and what stands in for the image

The design's statement ends "and none of them appears in the image content". There is no MicroVM
image in the offline suite — building one needs the IaC package, which is a later phase — but the
part of the image this requirement is about is present and is the part a captured value would be
captured *into*: the Python source the image ships. `IMAGE_CONTENT` is every `runtime/**/*.py` byte,
and no generated value occurs in it. That catches the literal form of the failure, a key pasted
into the source as a constant, which is the one form of "captured during image build" that survives
in the artifact rather than only in a running process.

## What is deliberately not asserted

The design's generator description names "the Family B certificate public key" as one of the three
collected values. There is no public key and no certificate signing request yet: producing one
needs an asymmetric algorithm and DER encoding, no crypto library is pinned, and the signing
exchange belongs to the Family B egress identity task. `egress_private_key` is raw key material
today, and it is the raw material's uniqueness that is asserted — which is the load-bearing half
anyway, since a public key derived from a shared private key would be shared for exactly the same
reason.

## Non-vacuity

Established by demonstration rather than by claim.
`test_a_batch_from_a_cached_implementation_fails_the_property` builds a batch from each of the
three defective generators named above — one caching at module scope, one in a class attribute, one
in a default argument — and asserts that `assert_pairwise_distinct`, the same function the property
calls, raises `AssertionError` for each. All three caches are drawn when *this* module is imported,
so they are faithful to the mechanism rather than analogies to it.

## Budget, and why the floor is the right number

The design's floor of 100 examples. One Sandbox through the full ASGI application measures about
0.8 ms, so a batch of up to five Sandboxes twice over is well inside the suite's 300-second budget
with room to spare, and the budget is not what limits the number. What limits it is that more
iterations buy nothing here: whether a value is cached at import is a fact about the module, fixed
before the first example runs, so the first example either reaches it or no number of examples
will. Iterations buy variety in batch size and in configuration shape, and 100 is ample for a
domain that size. This is not a property where a rare draw is the failure.

## Deviation from the design's placement

The design's generator says the batch is started "against the `local-firecracker` provider". That
provider simulates the Compute_Provider contract — it records a provisioned Sandbox and issues a
loopback `base_url` — and hosts no Sandbox_Runtime for a `/run` to reach, so routing through it
would place a simulation between the assertion and the code R7.12 is about while adding nothing:
nothing in this property is about provisioning. The Sandboxes here are driven over the same ASGI
application the MicroVM image runs, which is what `tests/test_property_5.py` does and for the same
reason.
"""

from __future__ import annotations

import itertools
import json
from collections.abc import Sequence
from dataclasses import dataclass
from http import HTTPStatus
from typing import Final

from hypothesis import given, settings
from hypothesis import strategies as st
from hypothesis.strategies import SearchStrategy
from starlette.testclient import TestClient

from protocol.schema import load_catalogue
from runtime.app import HOOK_PATH_PREFIX, create_app
from runtime.lifecycle import SandboxLifecycle
from runtime.operations import OperationRegistry
from runtime.ports import ExposedPorts
from runtime.readiness import ReadinessGate, RuntimePhase
from runtime.session_values import SessionValues
from tests.harness import MINIMUM_EXAMPLES, REPOSITORY_ROOT

CATALOGUE: Final = load_catalogue()

#: A uniqueness claim needs two Sandboxes to be a claim at all, and the upper bound is small
#: because a batch of five reaches every failure mode a batch of fifty would: a cache is shared by
#: all of them or by none.
MIN_BATCH: Final = 2
MAX_BATCH: Final = 5

#: The characters a drawn hostname is built from. The endpoint URL template is drawn only so that
#: the hook is reached over more than one configuration document; its contents are Property 9's
#: subject, so the alphabet is the boring one rather than an adversarial one.
_HOST_ALPHABET: Final = "abcdefghijklmnopqrstuvwxyz0123456789-"

_MIN_PORT: Final = 1
_MAX_PORT: Final = 65535

#: The packages the MicroVM image ships: the runtime itself and the protocol it speaks.
_IMAGE_PACKAGES: Final = ("runtime", "protocol")

#: Every byte of Python source in those packages. This is what stands in for "the image content"
#: in the design's second conjunct: a value captured during image build and baked into the
#: artifact is a literal in one of these files. See the module docstring. The set grows as the
#: image gains modules, which is the right direction for a haystack.
IMAGE_CONTENT: Final = b"\n".join(
    path.read_bytes()
    for package in _IMAGE_PACKAGES
    for path in sorted((REPOSITORY_ROOT / package).rglob("*.py"))
)

#: The two fields whose whole premise is that they never leave the MicroVM, so a `repr` must not
#: render them. `instance_id` is not one of them: it is an identifier that appears in log stream
#: names, and withholding it would make a traceback useless for no gain.
WITHHELD_FIELDS: Final = ("process_handle_key", "egress_private_key")


@dataclass(frozen=True, slots=True)
class Generated:
    """One Sandbox's per-Session values, labelled with how that Sandbox was started.

    The label exists so that a failure can name *which* two Sandboxes collided without rendering
    any part of the colliding value. This is the one place in the suite where that distinction
    matters: an assertion message reaches the CI log, and the Family B key is a value whose whole
    premise is that it never leaves the MicroVM.
    """

    origin: str
    values: SessionValues


def fields_of(values: SessionValues) -> dict[str, str | bytes]:
    """The three per-Session values by name, so a comparison can report which one collided."""
    return {
        "instance_id": values.instance_id,
        "process_handle_key": values.process_handle_key,
        "egress_private_key": values.egress_private_key,
    }


# --- The assertions the property makes, each usable on its own -----------------------------


def assert_pairwise_distinct(batch: Sequence[Generated]) -> None:
    """No two Sandboxes in the batch share any of the three values.

    Every pair, not every adjacent pair: a generator alternating between two cached values would
    pass a consecutive-element comparison and is as much of an R7.12 violation as one cached value.
    """
    assert len(batch) >= MIN_BATCH, (
        f"a uniqueness claim needs at least {MIN_BATCH} Sandboxes to be a claim; this batch "
        f"has {len(batch)}"
    )
    for left, right in itertools.combinations(batch, 2):
        right_fields = fields_of(right.values)
        shared = sorted(
            name
            for name, value in fields_of(left.values).items()
            if value == right_fields[name]
        )
        # The message names the pair and the field. It never renders the value: a shared secret
        # written into a CI log would be a second, worse failure on top of the first.
        assert not shared, (
            f"{left.origin} and {right.origin} were started from one import of "
            f"runtime.session_values and share {shared}; a value shared across Sandboxes from "
            f"one image version is a value captured during image build (R7.12)"
        )


def assert_no_value_is_in_the_image(generated: Generated) -> None:
    """None of the values occurs in the Python source the image ships (R7.12)."""
    for name, value in fields_of(generated.values).items():
        needle = value.encode() if isinstance(value, str) else value
        assert needle not in IMAGE_CONTENT, (
            f"{generated.origin}'s {name} occurs in the runtime source the image ships, so it "
            f"is image content rather than a value generated inside this Sandbox (R7.12)"
        )


def assert_only_the_identifier_survives_a_repr(generated: Generated) -> None:
    """The `repr` carries `instance_id` and neither secret.

    Part of what makes the values *usable* rather than merely unique: a value that reaches a
    traceback has left the MicroVM, and the two keys are the values that must not.
    """
    rendered = repr(generated.values)
    assert generated.values.instance_id in rendered, (
        f"{generated.origin}'s repr withholds instance_id, which is a log stream name rather "
        f"than a secret and is what makes the repr worth having"
    )
    fields = fields_of(generated.values)
    for name in WITHHELD_FIELDS:
        secret = fields[name]
        assert isinstance(secret, bytes)
        for rendering in (secret.hex(), repr(secret), str(secret)):
            assert rendering not in rendered, (
                f"{generated.origin}'s repr renders {name}, so an unhandled exception's "
                f"traceback carries it out of the MicroVM"
            )


# --- Starting a Sandbox, the two ways in ---------------------------------------------------


def start_through_the_run_hook(payload: bytes, *, label: str) -> Generated:
    """Drive one Sandbox's `/run` over the real application and return what it published.

    The whole application, the real readiness gate and the real port registry, because R7.12 is
    about the values a `/run` generates and `SandboxLifecycle.apply_configuration` is reached the
    way the MicroVM reaches it. No filesystem root and no State_Store reader are bound: neither is
    needed by a configuration that restores nothing, and a runtime without them is a truthful
    configuration rather than a stubbed one.
    """
    gate = ReadinessGate()
    ports = ExposedPorts(catalogue=CATALOGUE)
    lifecycle = SandboxLifecycle(ports=ports)
    operations = OperationRegistry(catalogue=CATALOGUE)
    ports.register(operations)
    app = create_app(
        actions=lifecycle, operations=operations, gate=gate, catalogue=CATALOGUE
    )

    started = TestClient(app).post(f"{HOOK_PATH_PREFIX}/run", content=payload)

    assert started.status_code == HTTPStatus.OK, (
        f"{label} did not start: {started.text}"
    )
    assert gate.phase is RuntimePhase.SERVING, (
        f"{label} returned 200 but its gate is {gate.phase}"
    )
    values = lifecycle.values
    assert values is not None, (
        f"{label} returned 200 having published no per-Session values, so R7.12's generation "
        f"step did not happen while the hook executed"
    )
    return Generated(origin=label, values=values)


def generate_directly(*, label: str) -> Generated:
    """One Sandbox's values from the generator the hook calls, reached without the hook."""
    return Generated(origin=label, values=SessionValues.generate())


def document(ports: list[int], host: str | None) -> bytes:
    """A configuration document a `/run` applies successfully.

    Three shapes are reachable and each is applicable: the empty document, a template with no
    declared ports, and a template with a port set. A document that *fails* to apply is deliberately
    out of the domain — it leaves the gate `FAILED` and publishes no values, which is a claim about
    R7.8 and belongs to Property 9.
    """
    body: dict[str, object] = {}
    if host is not None or ports:
        name = host if host is not None else "sandbox"
        body["endpointUrlTemplate"] = f"https://{name}.endpoint.example/ports/{{port}}"
    if ports:
        body["exposedPorts"] = sorted(ports)
    return json.dumps(body).encode()


def run_payload() -> SearchStrategy[bytes]:
    """Draw one applicable configuration document."""
    return st.builds(
        document,
        ports=st.lists(
            st.integers(min_value=_MIN_PORT, max_value=_MAX_PORT),
            max_size=3,
            unique=True,
        ),
        host=st.none() | st.text(alphabet=_HOST_ALPHABET, min_size=1, max_size=12),
    )


# Feature: aws-serverless-agent-sandbox, Property 10: For all sets of Sandboxes started from a
# single Sandbox image version, the per-Session unique values each Sandbox generates are pairwise
# distinct, and none of them appears in the image content.
@given(payloads=st.lists(run_payload(), min_size=MIN_BATCH, max_size=MAX_BATCH))
@settings(max_examples=MINIMUM_EXAMPLES)
def test_per_session_values_are_unique_across_sandboxes_from_one_image_version(
    payloads: list[bytes],
) -> None:
    through_the_hook = [
        start_through_the_run_hook(payload, label=f"the /run Sandbox {index}")
        for index, payload in enumerate(payloads)
    ]
    directly = [
        generate_directly(label=f"the direct Sandbox {index}")
        for index in range(len(payloads))
    ]
    # One batch, because every one of these Sandboxes was started from this file's single import
    # of runtime.session_values, which is what "one image version" means in one process.
    batch = [*through_the_hook, *directly]

    assert_pairwise_distinct(batch)
    for generated in batch:
        assert_no_value_is_in_the_image(generated)
        assert_only_the_identifier_survives_a_repr(generated)


# --- Non-vacuity: the three ways the design names of failing R7.12 ------------------------
#
# Each of the three caches below is drawn when this module is imported, which is when the
# Sandbox_Runtime is imported during an image build. They are the mechanism, not an analogy to it.

#: A module-level constant.
_MODULE_SCOPE_CACHE: Final = SessionValues.generate()


class _ClassAttributeCache:
    """A class attribute, drawn once when this class body executed."""

    cached: Final = SessionValues.generate()

    @classmethod
    def generate(cls) -> SessionValues:
        return cls.cached


def _from_a_default_argument(
    # The defect being demonstrated: Python evaluates this default exactly once, when the module
    # is imported, so the value it holds is image content however per-call the signature looks.
    cached: SessionValues = SessionValues.generate(),  # noqa: B008 - the defect under demonstration
) -> SessionValues:
    """A default argument, which is the subtlest of the three."""
    return cached


def test_a_batch_from_a_cached_implementation_fails_the_property() -> None:
    """The property is non-vacuous: each named failure mode is caught by the same assertion.

    `assert_pairwise_distinct` is the function the property calls, applied here to batches built
    from generators that cache. If any of these three passed, the property above would be
    asserting nothing about R7.12's adversary.
    """
    defective = {
        "a module-level constant": lambda: _MODULE_SCOPE_CACHE,
        "a class attribute": _ClassAttributeCache.generate,
        "a default argument": _from_a_default_argument,
    }

    for description, generate in defective.items():
        batch = [
            Generated(origin=f"{description}, Sandbox {index}", values=generate())
            for index in range(MAX_BATCH)
        ]
        # `pytest.raises` is not used: the point is that this exact call fails, and the reason it
        # fails is worth reading, so it is caught and checked rather than merely expected.
        try:
            assert_pairwise_distinct(batch)
        except AssertionError as failure:
            assert "captured during image build" in str(failure)
            assert "'egress_private_key'" in str(failure)
        else:
            raise AssertionError(
                f"a runtime caching its per-Session values in {description} passed the "
                f"uniqueness assertion, so the property proves nothing about R7.12"
            )


def test_a_batch_of_one_is_not_a_uniqueness_claim() -> None:
    """The lower bound is load-bearing: a batch of one is pairwise distinct for free."""
    single = [generate_directly(label="the only Sandbox")]

    try:
        assert_pairwise_distinct(single)
    except AssertionError as failure:
        assert "needs at least 2 Sandboxes" in str(failure)
    else:
        raise AssertionError(
            "a batch of one satisfied the uniqueness assertion, so a shrunk counterexample "
            "could pass by having nothing to compare"
        )


def test_a_value_baked_into_the_image_source_is_found() -> None:
    """The second conjunct is non-vacuous, and the haystack it searches is the real one.

    An `IMAGE_CONTENT` that had come back empty — a wrong path, a glob that matched nothing —
    would make `assert_no_value_is_in_the_image` pass for every input while looking like it
    asserted something. So the haystack is checked, and then a `SessionValues` whose identifier is
    a literal from the runtime source is run through the same search the property performs.
    """
    assert b"class SessionValues" in IMAGE_CONTENT
    assert b"secrets.token_bytes" in IMAGE_CONTENT
    assert len(IMAGE_CONTENT) > 10_000

    baked_in = Generated(
        origin="a Sandbox whose identifier is a literal in the image",
        # Not a plausible identifier, and it does not need to be: what is being demonstrated is
        # that the search finds a value the image already carries, whatever shape it has.
        values=SessionValues(
            instance_id="class SessionValues",
            process_handle_key=b"k" * 32,
            egress_private_key=b"e" * 32,
        ),
    )

    try:
        assert_no_value_is_in_the_image(baked_in)
    except AssertionError as failure:
        assert "occurs in the runtime source the image ships" in str(failure)
    else:
        raise AssertionError(
            "a value present in the shipped runtime source passed the image-content "
            "assertion, so the design's second conjunct is asserting nothing"
        )
