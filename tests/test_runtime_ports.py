# kiro-classification: public
"""Exposed-port passthrough: which ports are exposable, and what a refusal says about why.

Deterministic, and no socket is opened anywhere in this file — which is the point rather than a
consequence of the offline suite's loopback-only rule. R7.6's mechanism is the endpoint's own port
routing, so the runtime registers a port and returns a URL; a test that had to bind something
would be a test of a runtime that had taken the endpoint's job.

The interesting assertions are the two refusals. A port the Session did not declare is refused
because no credential the Control_Plane can issue is scoped to it, and an unconfigured runtime is
refused because the URL shape arrives with the per-Session configuration and cannot be guessed.
"""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine

import pytest

from protocol.codec.messages import decode, encode
from protocol.codec.values import Message
from protocol.schema import (
    ENVELOPE_KEY_BODY,
    ENVELOPE_KEY_ID,
    ENVELOPE_KEY_TYPE,
    ENVELOPE_KEY_VERSION,
    load_catalogue,
)
from runtime.operations import OperationRegistry, OperationReply
from runtime.ports import (
    PORT_EXPOSE,
    PORT_PLACEHOLDER,
    PORT_URL,
    ExposedPorts,
    PortRouting,
    TemplatePortRouting,
)
from runtime.protocol_handler import SandboxProtocolHandler
from runtime.readiness import ReadinessGate

CATALOGUE = load_catalogue()

#: A template of the shape a deployment would configure: the endpoint host is per-Session and
#: the port is substituted into it. Nothing in the repository resolves this name.
TEMPLATE = "https://sandbox-9f3.endpoint.invalid/ports/{port}/"


def run[T](coroutine: Coroutine[object, object, T]) -> T:
    return asyncio.run(coroutine)


def expose_request(port: int) -> Message:
    message = CATALOGUE.messages[PORT_EXPOSE]
    return {
        ENVELOPE_KEY_VERSION: CATALOGUE.protocol_version,
        ENVELOPE_KEY_TYPE: PORT_EXPOSE,
        ENVELOPE_KEY_ID: b"cid",
        ENVELOPE_KEY_BODY: {message.field_by_name("port").key: port},
    }


def body(reply: OperationReply) -> dict[str, object]:
    return {
        field.name: reply.body[field.key]
        for field in CATALOGUE.messages[reply.t].body
        if field.key in reply.body
    }


def refusal(reply: OperationReply) -> str:
    """The detail of an `error.decode` reply, having asserted it names the `port` field."""
    assert reply.t == "error.decode"
    fields = body(reply)
    assert fields["field"] == "port"
    detail = fields["detail"]
    assert isinstance(detail, str)
    return detail


def configured(*declared: int) -> ExposedPorts:
    ports = ExposedPorts(catalogue=CATALOGUE)
    ports.configure(declared=declared, routing=TemplatePortRouting(TEMPLATE))
    return ports


# --- Exposing a declared port ---------------------------------------------------------------


def test_a_declared_port_is_registered_and_answered_with_its_endpoint_url() -> None:
    ports = configured(8080, 3000)
    assert ports.registered == frozenset()

    reply = run(ports.expose(expose_request(8080)))
    assert reply.t == PORT_URL
    assert body(reply) == {"url": "https://sandbox-9f3.endpoint.invalid/ports/8080/"}
    assert ports.registered == frozenset({8080})


def test_registration_does_not_require_anything_to_be_listening() -> None:
    """The application inside the Sandbox listens; the runtime records and does not probe.

    Nothing is bound on 8080 in this process, and the operation succeeds anyway. A runtime that
    checked would have to decide what "listening" means for a server that has bound but not yet
    accepted, and would answer a caller's `port.expose` with a race.
    """
    reply = run(configured(8080).expose(expose_request(8080)))
    assert reply.t == PORT_URL


def test_exposing_the_same_port_twice_is_the_same_answer() -> None:
    ports = configured(8080)
    first = run(ports.expose(expose_request(8080)))
    second = run(ports.expose(expose_request(8080)))
    assert body(first) == body(second)
    assert ports.registered == frozenset({8080})


# --- Refusals -------------------------------------------------------------------------------


def test_an_undeclared_port_is_refused_because_no_credential_is_scoped_to_it() -> None:
    """The credential-scoping consequence: a URL no token can authenticate against is not a URL."""
    ports = configured(8080)
    reply = run(ports.expose(expose_request(9999)))

    detail = refusal(reply)
    assert "declared exposed ports" in detail
    assert "credential" in detail
    assert ports.registered == frozenset()


def test_a_session_that_declared_no_ports_can_expose_none() -> None:
    """Such a Session's credential is scoped to the control port alone, so there is nothing."""
    ports = ExposedPorts(catalogue=CATALOGUE)
    ports.configure(declared=(), routing=TemplatePortRouting(TEMPLATE))
    assert "declared exposed ports" in refusal(run(ports.expose(expose_request(8080))))


def test_an_unconfigured_runtime_refuses_rather_than_inventing_a_url() -> None:
    """Before `/run`, the endpoint's URL shape is unknown and a plausible guess is worse than no
    answer: it is indistinguishable from a real URL to its caller and wrong only in production."""
    ports = ExposedPorts(catalogue=CATALOGUE, declared=(8080,))
    assert "no endpoint port routing is configured" in refusal(
        run(ports.expose(expose_request(8080)))
    )


# --- Configuration --------------------------------------------------------------------------


def test_configure_replaces_rather_than_accumulates() -> None:
    """One `/run` configures one Session; a port set spanning two describes neither."""
    ports = configured(8080)
    run(ports.expose(expose_request(8080)))
    assert ports.registered == frozenset({8080})

    ports.configure(declared=(3000,), routing=TemplatePortRouting(TEMPLATE))
    assert ports.declared == frozenset({3000})
    assert ports.registered == frozenset()
    assert "declared exposed ports" in refusal(run(ports.expose(expose_request(8080))))


def test_a_template_without_the_placeholder_is_refused_at_construction() -> None:
    """It would return one URL for every port, which looks like it worked and reaches the wrong
    application."""
    with pytest.raises(ValueError, match=r"\{port\}"):
        TemplatePortRouting("https://sandbox-9f3.endpoint.invalid/")


def test_the_placeholder_is_substituted_everywhere_it_appears() -> None:
    routing = TemplatePortRouting(
        f"https://{PORT_PLACEHOLDER}.sandbox.invalid/{PORT_PLACEHOLDER}"
    )
    assert routing.url_for(3000) == "https://3000.sandbox.invalid/3000"


def test_routing_is_a_protocol_so_a_deployment_supplies_its_own_url_shape() -> None:
    """The seam: one method, port in and URL out. The concrete shape is the deployment's."""

    class SubdomainRouting:
        def url_for(self, port: int) -> str:
            return f"https://p{port}-sandbox-9f3.endpoint.invalid/"

    routing: PortRouting = SubdomainRouting()
    assert isinstance(routing, PortRouting)

    ports = ExposedPorts(catalogue=CATALOGUE)
    ports.configure(declared=(3000,), routing=routing)
    reply = run(ports.expose(expose_request(3000)))
    assert body(reply) == {"url": "https://p3000-sandbox-9f3.endpoint.invalid/"}


# --- Through the protocol handler ------------------------------------------------------------


def test_the_operation_encodes_against_the_catalogue_end_to_end() -> None:
    """`port.url` carries text where every other payload field in the catalogue carries bytes.

    That makes it the field most likely to be built wrongly, and the unit tests above never
    encode, so they would not notice. This one goes through the real handler and the real codec.
    """

    async def scenario() -> None:
        gate = ReadinessGate()
        registry = OperationRegistry(catalogue=CATALOGUE)
        configured(8080).register(registry)
        handler = SandboxProtocolHandler(
            gate=gate, operations=registry, catalogue=CATALOGUE
        )
        await gate.begin_start()
        await gate.finish_start()

        async def exchange(port: int) -> Message:
            reply = await handler.handle(
                encode(expose_request(port), catalogue=CATALOGUE)
            )
            assert reply.wire is not None, reply.reason
            return decode(reply.wire, catalogue=CATALOGUE)

        exposed = await exchange(8080)
        assert exposed[ENVELOPE_KEY_TYPE] == PORT_URL

        refused = await exchange(9999)
        assert refused[ENVELOPE_KEY_TYPE] == "error.decode"

    run(scenario())


# --- Registration ---------------------------------------------------------------------------


def test_only_port_expose_is_routed() -> None:
    registry = OperationRegistry(catalogue=CATALOGUE)
    configured(8080).register(registry)
    assert registry.routed() == {PORT_EXPOSE}
    # `port.url` is a reply, so the registry would refuse it; asserting its absence records
    # that this module does not try to route what it answers with.
    assert PORT_URL not in registry.routed()
