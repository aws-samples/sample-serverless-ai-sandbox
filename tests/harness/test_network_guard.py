# kiro-classification: public
"""The guard that keeps the suite offline is itself asserted, not assumed (R15.9)."""

from __future__ import annotations

import socket
from collections.abc import Iterator

import pytest

from tests.harness import NetworkGuard, OutboundNetworkDenied, is_loopback_host


@pytest.fixture
def loopback_server() -> Iterator[tuple[str, int]]:
    """A listening socket on loopback, which the offline suite is allowed to reach."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        yield listener.getsockname()


def test_outbound_connection_is_denied() -> None:
    with (
        pytest.raises(OutboundNetworkDenied) as denial,
        socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client,
    ):
        client.connect(("93.184.216.34", 443))
    assert "93.184.216.34:443" in str(denial.value)


def test_outbound_name_resolution_is_denied() -> None:
    with pytest.raises(OutboundNetworkDenied):
        socket.getaddrinfo("dynamodb.eu-west-1.amazonaws.com", 443)


def test_loopback_connection_is_permitted(loopback_server: tuple[str, int]) -> None:
    with socket.create_connection(loopback_server, timeout=5) as connection:
        assert connection.getpeername()[0] == "127.0.0.1"


def test_loopback_name_resolution_is_permitted() -> None:
    assert socket.getaddrinfo("localhost", 0)


@pytest.mark.parametrize(
    "host",
    ["localhost", "127.0.0.1", "127.0.0.53", "::1", "", "0.0.0.0", b"127.0.0.1"],  # nosec B104
)
def test_local_hosts_are_recognised(host: object) -> None:
    assert is_loopback_host(host)


@pytest.mark.parametrize(
    "host",
    [
        "example.com",
        "93.184.216.34",
        "2606:2800:220:1:248:1893:25c8:1946",
        "169.254.169.254",
    ],
)
def test_remote_hosts_are_recognised(host: str) -> None:
    assert not is_loopback_host(host)


def test_guard_restores_the_socket_module() -> None:
    """A guard that could not be removed would make its own tests untrustworthy."""
    original_connect = socket.socket.connect
    guard = NetworkGuard()
    guard.install()
    assert guard.installed
    assert socket.socket.connect is not original_connect
    guard.uninstall()
    assert not guard.installed
    assert socket.socket.connect is original_connect


def test_installing_twice_is_idempotent() -> None:
    guard = NetworkGuard()
    guard.install()
    patched_connect = socket.socket.connect
    guard.install()
    assert socket.socket.connect is patched_connect
    guard.uninstall()
    assert socket.socket.connect is not patched_connect
