# kiro-classification: public
"""Exposed-port passthrough: registering a port, and returning the endpoint URL that reaches it.

This is the `Exposed-port passthrough` node of the design's Sandbox_Runtime drawing, and the word
*passthrough* is the whole of the design in it. R7.6 asks the runtime to expose an application
listening on a Sandbox-internal port "using the documented port routing mechanism", and the design
names that mechanism rather than leaving it open: the MicroVM has a dedicated HTTPS endpoint in
front of it, and the capability table says "Documented endpoint port routing; the Runtime
registers the port set and the caller's token must be scoped to that port".

So the runtime does not route anything. It does not bind a socket, does not proxy, does not listen
on the caller's behalf and does not check that anything is listening on the port it is asked
about. All three of those would be the runtime re-implementing the endpoint it sits behind, and
the last one would additionally be a probe against the Sandbox's own loopback that could hang or
lie — a server that has bound but not yet accepted is indistinguishable from one that never will.
The application inside the Sandbox listens; the endpoint forwards; this module records which ports
the Session may be reached on and answers with the URL that reaches one.

## The credential-scoping consequence

The interesting part is what happens for a port the Session did not declare, and the answer is
fixed by something outside this module. `runtime.server` records that the Control_Plane scopes
every issued credential to the protocol port together with the Session's declared exposed ports;
the design's issuance rules put it precisely — `ports` is "the intersection of the Session's
declared `exposed_ports` and the Sandbox_Protocol control port", and a Session that declared none
gets a token scoped to the control port alone. The permission to mint that token belongs to the
Control_Plane execution role and to nothing inside the MicroVM.

Therefore a URL for an undeclared port is a URL no credential in existence can authenticate
against. Returning one would be answering "here is how to reach it" with a string that cannot
reach it, and the caller's failure would surface at the endpoint as an authorisation error about a
port, which is a long way from the operation that caused it. `port.expose` for an undeclared port
is refused, naming the reason, so the caller learns it at the point of asking. The declared set is
the sole authority on this: this module does not decide which ports are exposable, it reports the
decision the Session's specification already made.

This is also why nothing here widens the set. There is no `port.expose` that adds a port to what
the credential permits — a runtime that could would be a runtime that could grant itself reach,
and the Control_Plane's monopoly on minting is what makes R11.4's scoping claim enforceable
rather than advisory. Registration records that an application is listening on a port the Session
already declared. It is bookkeeping plus a URL, and it is meant to be.

## The seam, and what is not built yet

Two inputs are per-Session and neither can be captured at image build time — R7.12 forbids it in
general, and the endpoint's hostname is not knowable before the MicroVM exists in any case:

- the declared exposed port set, which the Session's specification carries;
- how to address a port on this Sandbox's endpoint, which is the deployed endpoint's own URL
  shape.

Both arrive with the per-Session configuration the `/run` hook applies, and `configure` is where
they land. The Control_Plane that composes that payload is phase 6 and the CDK that deploys the
endpoint is phase 12, so neither exists yet and the concrete URL shape is not this task's to
invent. `PortRouting` is the seam: one method, port in and URL out, with `TemplatePortRouting`
as the form a deployment-configured template takes. Until `configure` has been called there is no
routing, and `port.expose` refuses rather than guessing — a fabricated URL would be indistinguish-
able from a real one to its caller and wrong in production only.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Final, Protocol, runtime_checkable

from protocol.codec.values import Message
from protocol.schema import Catalogue, load_catalogue
from runtime.bodies import (
    OperationRefusal,
    as_uint,
    named_body,
    refusal_reply,
    request_fields,
)
from runtime.operations import OperationRegistry, OperationReply

__all__ = [
    "PORT_EXPOSE",
    "PORT_PLACEHOLDER",
    "PORT_URL",
    "ExposedPorts",
    "PortRouting",
    "TemplatePortRouting",
]

#: The catalogue's two exposed-port types.
PORT_EXPOSE: Final = "port.expose"
PORT_URL: Final = "port.url"

#: The field every refusal here names. The catalogue already constrains it to 1..65535, so an
#: out-of-range port is a decode error raised by the codec and never reaches this module.
_PORT: Final = "port"

#: What a configured URL template substitutes. Named rather than spelled inline so a deployment
#: reading this module and a deployment writing the template are reading one spelling.
PORT_PLACEHOLDER: Final = "{port}"


@runtime_checkable
class PortRouting(Protocol):
    """How a Sandbox-internal port is addressed on this Sandbox's endpoint.

    A Protocol with one method, because that is the entire dependency: the runtime knows the port
    and the deployment knows the URL shape, and nothing else passes between them. A concrete
    class here would be this module asserting an endpoint URL shape it has no standing to assert.
    """

    def url_for(self, port: int) -> str:
        """The URL through which the caller reaches `port` on this Sandbox."""
        ...


@dataclass(frozen=True, slots=True)
class TemplatePortRouting:
    """Routing by a deployment-configured URL template containing `{port}`.

    The template is data delivered with the per-Session configuration, not a constant, so the
    same runtime image serves a deployment whose endpoint addresses ports by subdomain and one
    that addresses them by path without a code change. The placeholder is required rather than
    optional: a template without it would return one URL for every port, which would look like it
    worked and reach the wrong application.
    """

    template: str

    def __post_init__(self) -> None:
        if PORT_PLACEHOLDER not in self.template:
            raise ValueError(
                f"an endpoint port routing template must contain {PORT_PLACEHOLDER!r}; "
                f"{self.template!r} would address every port identically"
            )

    def url_for(self, port: int) -> str:
        """Substitute the port into the template."""
        return self.template.replace(PORT_PLACEHOLDER, str(port))


class ExposedPorts:
    """The registered port set for one Session, and the `port.expose` operation over it.

    Starts unconfigured, which is the same stance `runtime.readiness` takes about the protocol
    handler and for the same reason: before `/run` has applied the per-Session configuration there
    is no declared port set and no endpoint to address, so there is no correct answer to give and
    an answer is not given.
    """

    def __init__(
        self,
        *,
        declared: Iterable[int] = (),
        routing: PortRouting | None = None,
        catalogue: Catalogue | None = None,
    ) -> None:
        self._catalogue = catalogue if catalogue is not None else load_catalogue()
        self._declared: frozenset[int] = frozenset(declared)
        self._routing = routing
        self._registered: set[int] = set()

    def configure(self, *, declared: Iterable[int], routing: PortRouting) -> None:
        """Apply the per-Session port configuration the `/run` hook received.

        Replaces rather than merges. A `/run` is the start of one Session's configuration, and a
        port set accumulated across two of them would describe no Session in particular — the
        readiness gate refuses a second `/run` for the same class of reason.
        """
        self._declared = frozenset(declared)
        self._routing = routing
        self._registered.clear()

    @property
    def declared(self) -> frozenset[int]:
        """The ports the Session declared, and therefore the ports a credential can be scoped to."""
        return self._declared

    @property
    def registered(self) -> frozenset[int]:
        """The declared ports an application inside the Sandbox has asked to be reached on."""
        return frozenset(self._registered)

    def register(self, registry: OperationRegistry) -> None:
        """Route `port.expose` onto this operation. `port.url` is a reply and is not routed."""
        registry.register(PORT_EXPOSE, self.expose)

    async def expose(self, request: Message) -> OperationReply:
        """`port.expose` -> `port.url`: register a declared port and return its endpoint URL."""
        fields = request_fields(self._catalogue, request)
        port = as_uint(fields[_PORT], _PORT)
        try:
            url = self._url_for(port)
        except OperationRefusal as refusal:
            return refusal_reply(self._catalogue, refusal)
        return OperationReply(
            t=PORT_URL, body=named_body(self._catalogue, PORT_URL, {"url": url})
        )

    def _url_for(self, port: int) -> str:
        if self._routing is None:
            raise OperationRefusal(
                _PORT,
                "no endpoint port routing is configured yet, so no URL reaches this Sandbox",
            )
        if port not in self._declared:
            raise OperationRefusal(
                _PORT,
                "is not among the Session's declared exposed ports, so no issued credential "
                "is scoped to it and no URL would reach it",
            )
        self._registered.add(port)
        return self._routing.url_for(port)
