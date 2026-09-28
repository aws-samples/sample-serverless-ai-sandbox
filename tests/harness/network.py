# kiro-classification: public
"""Denial of outbound network access for the offline suite (R15.9).

The offline suite runs with no deployed AWS resources and no network access. CI enforces
that at the operating-system level (`ci/deny-egress.sh`); this module enforces the same
rule in-process, so a developer running `make test` on a workstation with working egress
gets the same verdict CI gets.

Loopback stays reachable on purpose. The offline suite talks to a local DynamoDB, the
`local-firecracker` provider and stubbed servers, all of which live on 127.0.0.1.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Any, Final

__all__ = [
    "NetworkGuard",
    "OutboundNetworkDenied",
    "is_loopback_host",
]

_GUIDANCE: Final = (
    "The offline suite runs with no deployed AWS resources and no network access "
    "(R15.9). Use the local-firecracker provider, a local DynamoDB, a "
    "recording transport or a stub instead."
)


class OutboundNetworkDenied(RuntimeError):
    """Raised when test code tries to reach a host outside loopback."""

    def __init__(self, target: str) -> None:
        super().__init__(f"Outbound network access denied: {target}. {_GUIDANCE}")
        self.target = target


_LOOPBACK_NAMES: Final = frozenset(
    {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}
)
# An unspecified address in a connect() call resolves to the local host.
_UNSPECIFIED_ADDRESSES: Final = frozenset({"", "0.0.0.0", "::"})  # nosec B104


def is_loopback_host(host: object) -> bool:
    """Report whether `host` names the local machine.

    Anything that is not a textual host is reported as loopback: address families other
    than AF_INET and AF_INET6 (AF_UNIX paths, AF_NETLINK integers) carry no destination
    this guard is meant to police, and denying them would be a false positive.
    """
    if isinstance(host, (bytes, bytearray)):
        try:
            host = bytes(host).decode("ascii")
        except UnicodeDecodeError:
            return True
    if not isinstance(host, str):
        return True
    if host in _LOOPBACK_NAMES or host in _UNSPECIFIED_ADDRESSES:
        return True
    try:
        # A scope identifier ("fe80::1%en0") is not part of the address itself.
        return ipaddress.ip_address(host.partition("%")[0]).is_loopback
    except ValueError:
        return False


def _describe(address: Any) -> str:
    if isinstance(address, tuple) and len(address) >= 2:
        return f"{address[0]}:{address[1]}"
    return repr(address)


def _target_host(address: Any) -> object:
    if isinstance(address, tuple) and address:
        return address[0]
    # AF_UNIX addresses are str or bytes paths, and are local by construction.
    return None


class NetworkGuard:
    """Patches the socket entry points that reach a remote host.

    Both `connect` and name resolution are covered: a denied name lookup means a test
    that would have leaked a DNS query fails before the query leaves the process.
    """

    def __init__(self) -> None:
        self._originals: dict[str, Any] = {}

    @property
    def installed(self) -> bool:
        return bool(self._originals)

    def install(self) -> None:
        if self.installed:
            return

        original_connect = socket.socket.connect
        original_connect_ex = socket.socket.connect_ex
        original_getaddrinfo = socket.getaddrinfo

        def guarded_connect(sock: socket.socket, address: Any, /) -> None:
            self._check_address(address)
            return original_connect(sock, address)

        def guarded_connect_ex(sock: socket.socket, address: Any, /) -> int:
            self._check_address(address)
            return original_connect_ex(sock, address)

        def guarded_getaddrinfo(host: Any, port: Any, *args: Any, **kwargs: Any) -> Any:
            if not is_loopback_host(host):
                raise OutboundNetworkDenied(f"name resolution for {host!r}")
            return original_getaddrinfo(host, port, *args, **kwargs)

        self._originals = {
            "connect": original_connect,
            "connect_ex": original_connect_ex,
            "getaddrinfo": original_getaddrinfo,
        }
        socket.socket.connect = guarded_connect  # type: ignore[assignment]
        socket.socket.connect_ex = guarded_connect_ex  # type: ignore[assignment]
        socket.getaddrinfo = guarded_getaddrinfo  # type: ignore[assignment]

    def uninstall(self) -> None:
        if not self.installed:
            return
        socket.socket.connect = self._originals["connect"]  # type: ignore[method-assign]
        socket.socket.connect_ex = self._originals["connect_ex"]  # type: ignore[method-assign]
        socket.getaddrinfo = self._originals["getaddrinfo"]
        self._originals = {}

    def _check_address(self, address: Any) -> None:
        if not is_loopback_host(_target_host(address)):
            raise OutboundNetworkDenied(_describe(address))
