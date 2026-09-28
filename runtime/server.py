# kiro-classification: public
"""The ASGI server: uvicorn, configured to be reachable only through the endpoint.

The design's drawing names uvicorn as the server, and this module is the whole of that node.
It is deliberately thin: the application is a plain ASGI callable (`runtime.app`) precisely so
that nothing about how it is bound to a socket can affect how it behaves, and so the offline
suite exercises the application without a server at all.

Two configuration choices are not incidental.

**The bind address defaults to loopback.** Inside the MicroVM, the only thing that should reach
this process is the provider's endpoint forwarding, which arrives locally. A default of
`0.0.0.0` would be reachable by anything else that ends up sharing a network namespace with the
Sandbox, and since this process performs no authentication of its own — the endpoint in front of
it does, and the design explains at length why a check here would be decorative — the bind
address is the one place in this module where a wrong default has a security consequence.
Overriding it is possible, because a provider whose forwarding does not arrive on loopback needs
to, and it is an explicit argument rather than a silent environment default for that reason.

**There is one worker.** The readiness gate and the process registry are per-process state, so a
second worker would be a second gate: `/run` would open one of them and the endpoint would
balance requests onto both, which is the readiness race R7.8 closes, reintroduced by a
deployment setting. A Sandbox serves one Session, so concurrency here is asyncio's and not a
process pool's.
"""

from __future__ import annotations

from typing import Final

import uvicorn
from starlette.applications import Starlette

__all__ = [
    "DEFAULT_HOST",
    "DEFAULT_PORT",
    "build_server",
    "serve",
]

#: Loopback, for the reason given above.
DEFAULT_HOST: Final = "127.0.0.1"

#: The Sandbox_Protocol control port. The Control_Plane scopes every issued credential to this
#: port together with the Session's declared exposed ports, so the number is part of the
#: deployment's contract rather than a local preference.
DEFAULT_PORT: Final = 8000


def build_server(
    app: Starlette,
    *,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
) -> uvicorn.Server:
    """Build the configured server without starting it.

    Separate from `serve` so that the configuration is assertable: the bind address and the
    worker count are the two settings with consequences, and a test can read them off the
    returned server rather than starting a socket to find out.
    """
    return uvicorn.Server(
        uvicorn.Config(
            app,
            host=host,
            port=port,
            # One gate per process, so one process. See the module docstring.
            workers=1,
            # The runtime's own logs are the Session-identifying emitter's, not uvicorn's
            # default access log, which would carry no Tenant or Session identity.
            access_log=False,
            lifespan="on",
        )
    )


def serve(
    app: Starlette,
    *,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
) -> None:
    """Run the application until the process is stopped."""
    build_server(app, host=host, port=port).run()
