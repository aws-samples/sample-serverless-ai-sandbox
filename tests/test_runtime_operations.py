# kiro-classification: public
"""The operation registry: what it will route, and what it refuses to route.

Registration is checked against the catalogue, so these are the three ways a wiring mistake is
caught at start-up rather than becoming a 501 someone reads in a log much later.
"""

from __future__ import annotations

import pytest

from protocol.codec.values import Message
from protocol.schema import Direction, load_catalogue
from runtime.operations import (
    INBOUND_DIRECTIONS,
    OperationRegistry,
    OperationReply,
    UnroutableMessageType,
    is_inbound,
)


async def _reply(request: Message) -> OperationReply:
    return OperationReply(t="fs.ack", body={})


def test_an_empty_registry_routes_nothing_and_is_not_an_error() -> None:
    registry = OperationRegistry()
    assert registry.routed() == frozenset()
    # Every inbound type is unrouted, which is a true report of a runtime with no operations.
    assert "exec.request" in set(registry.unrouted_inbound())


def test_registering_an_inbound_type_routes_it() -> None:
    registry = OperationRegistry()
    registry.register("session.quiesce", _reply)
    assert registry.routed() == frozenset({"session.quiesce"})
    assert registry.operation_for("session.quiesce") is _reply
    assert registry.operation_for("exec.request") is None
    assert "session.quiesce" not in set(registry.unrouted_inbound())


def test_a_type_the_catalogue_does_not_declare_is_refused() -> None:
    registry = OperationRegistry()
    with pytest.raises(UnroutableMessageType, match="no message type"):
        registry.register("fs.raed", _reply)


def test_a_type_the_runtime_only_sends_is_refused() -> None:
    """`exec.result` is `runtime-to-client`; routing it would be answering our own replies."""
    registry = OperationRegistry()
    with pytest.raises(UnroutableMessageType, match="runtime-to-client"):
        registry.register("exec.result", _reply)


def test_two_registrations_for_one_type_are_refused() -> None:
    registry = OperationRegistry()
    registry.register("session.quiesce", _reply)
    with pytest.raises(UnroutableMessageType, match="already routed"):
        registry.register("session.quiesce", _reply)


def test_inbound_directions_are_the_three_that_reach_the_runtime() -> None:
    assert INBOUND_DIRECTIONS == {
        Direction.CLIENT_TO_RUNTIME,
        Direction.ORCHESTRATOR_TO_RUNTIME,
        Direction.BOTH,
    }
    assert is_inbound("exec.request")  # client-to-runtime
    assert is_inbound("session.quiesce")  # orchestrator-to-runtime
    assert is_inbound("pty.data")  # both
    assert not is_inbound("exec.result")  # runtime-to-client
    assert not is_inbound("nope.nope")  # not declared at all


def test_every_catalogue_type_is_classified_one_way_or_the_other() -> None:
    """No message type is left out of the routing decision by a direction nobody handles."""
    catalogue = load_catalogue()
    for t in catalogue.message_types:
        direction = catalogue.messages[t].direction
        assert is_inbound(t) == (direction in INBOUND_DIRECTIONS)
