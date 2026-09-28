# kiro-classification: public
"""Sandbox interaction helper — sends Sandbox_Protocol requests to the MicroVM endpoint.

Uses the Protocol_Codec from ``protocol/codec/`` to serialise and deserialise messages.  The
connection credential (the ``X-aws-proxy-auth`` JWE token) is attached to every request.

This is a minimal helper for the Demo_Application, NOT the full Client_SDK (paused in Tier 3).
"""

from __future__ import annotations

import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Final

from protocol.codec import Message, Value, decode, encode
from protocol.schema import (
    ENVELOPE_KEY_BODY,
    ENVELOPE_KEY_ID,
    ENVELOPE_KEY_TYPE,
    ENVELOPE_KEY_VERSION,
    load_catalogue,
)

__all__ = ["SandboxClient"]

#: Default protocol version emitted by the demo client.
_PROTOCOL_VERSION: Final = load_catalogue().protocol_version


@dataclass(frozen=True, slots=True)
class SandboxClient:
    """Send Sandbox_Protocol requests to a MicroVM endpoint.

    Parameters
    ----------
    base_url:
        The dedicated HTTPS endpoint for the Sandbox (from the connection descriptor).
    auth_header_name:
        The header name the endpoint requires (typically ``X-aws-proxy-auth``).
    auth_header_value:
        The JWE token value to attach.
    """

    base_url: str
    auth_header_name: str
    auth_header_value: str

    @classmethod
    def from_connection(cls, connection: dict[str, Any]) -> SandboxClient:
        """Build a client from the ``connection`` map returned by the Control_Plane."""
        return cls(
            base_url=connection["baseUrl"],
            auth_header_name=connection["authHeaderName"],
            auth_header_value=connection["authHeaderValue"],
        )

    # ------------------------------------------------------------------
    # High-level operations
    # ------------------------------------------------------------------

    def execute(
        self,
        command: list[str],
        *,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        timeout_seconds: int = 60,
    ) -> dict[str, Any]:
        """Execute a command inside the Sandbox and return the result.

        Streams ``exec.chunk`` messages until ``exec.result`` arrives.
        """
        body: dict[int, Any] = {
            1: [arg.encode() for arg in command],  # argv: list[bytes]
            2: (cwd or "/tmp").encode(),           # cwd: bytes (required)  # nosec B108
            3: {k.encode(): v.encode() for k, v in (env or {}).items()},  # env: map (required)
            4: timeout_seconds * 1000,             # timeoutMs: uint (milliseconds)
            5: False,                              # stream: bool
        }

        response = self._send("exec.request", body)
        return self._body_to_dict(response)

    def write_file(self, path: str, content: bytes, *, mode: int = 0o644) -> None:
        """Write a file inside the Sandbox (R16.5)."""
        body: dict[int, Any] = {
            1: path.encode(),   # path: bytes
            2: content,         # content: bytes
            3: mode,            # mode: uint
        }
        self._send("fs.write", body)

    def read_file(self, path: str) -> bytes:
        """Read a file from the Sandbox (R16.5)."""
        body: dict[int, Any] = {1: path.encode()}  # path: bytes
        response = self._send("fs.read", body)
        # fs.content body: key 4 is the body map, key 1 inside it is the content (bytes).
        response_body = response[ENVELOPE_KEY_BODY]
        assert isinstance(response_body, dict)
        content = response_body[1]
        assert isinstance(content, bytes)
        return content

    # ------------------------------------------------------------------
    # Protocol transport
    # ------------------------------------------------------------------

    def _send(self, message_type: str, body: dict[int, Any]) -> Message:
        """Serialise, send, and return the decoded response message."""
        request_id = os.urandom(16)
        # Build the envelope map — cast body values into the Value space for the codec.
        body_value: dict[Value, Value] = {k: v for k, v in body.items()}
        message: Message = {
            ENVELOPE_KEY_VERSION: _PROTOCOL_VERSION,
            ENVELOPE_KEY_TYPE: message_type,
            ENVELOPE_KEY_ID: request_id,
            ENVELOPE_KEY_BODY: body_value,
        }
        wire = encode(message)

        url = self.base_url.rstrip("/") + "/protocol"
        headers = {
            self.auth_header_name: self.auth_header_value,
            "Content-Type": "application/cbor",
        }
        req = urllib.request.Request(url, data=wire, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req) as resp: # nosec B310 # nosemgrep: dynamic-urllib-use-detected
                return decode(resp.read())
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode(errors="replace")
            raise RuntimeError(
                f"Sandbox returned HTTP {exc.code} for {message_type}: {raw!r}"
            ) from exc

    @staticmethod
    def _body_to_dict(message: Message) -> dict[str, Any]:
        """Convert a protocol message body to a human-readable dict for reporting."""
        body = message[ENVELOPE_KEY_BODY]
        result: dict[str, Any] = {}
        for key, value in body.items():  # type: ignore[union-attr]
            label = f"field_{key!r}" if not isinstance(key, str) else key
            if isinstance(value, bytes):
                result[str(label)] = value.decode(errors="replace")
            else:
                result[str(label)] = value
        return result
