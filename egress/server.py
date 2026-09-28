# kiro-classification: public
"""Egress proxy server for the Fargate fleet (R12.1, R12.6, R16.2).

PCSR Finding 7: this is the deployed I/O shell. All egress decisions are delegated to
``Interceptor.intercept()`` from ``egress.interception``, which enforces tier separation,
Host/SNI validation, echo denylists, and the closed policy model.

Listens on TCP:443 and handles two kinds of inbound connection from MicroVMs:

- **CONNECT tunnel (Tier 3)**: standard HTTP CONNECT for allowed destinations.
- **HTTP forward proxy (Tier 1/2)**: SigV4 re-signing or token injection for allowed services.

The egress policy is read from DynamoDB via the ``DDBPolicySource`` adapter every 30s
(configurable). Operators change the policy via ``put-item`` — no proxy restart needed.
"""

from __future__ import annotations

import asyncio
import logging
import os
import ssl
import sys
from typing import Final
from urllib.parse import urlparse

import botocore.auth
import botocore.awsrequest
import botocore.session

from egress.adapters import BotocoreSigner, DDBPolicySource, SecretsManagerTokens
from egress.interception import (
    Denied,
    Forwarded,
    Injection,
    InterceptionSettings,
    Interceptor,
    TerminatedRequest,
    TunnelledConnection,
    Tunnelled,
)
from egress.reader import CachedPolicyReader, PolicyCacheSettings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("egress-proxy")

LISTEN_PORT: Final[int] = int(os.environ.get("PROXY_PORT", "443"))
_IDLE_TIMEOUT: Final[int] = 300
_CONNECT_TIMEOUT: Final[int] = 10
_PIPE_BUFFER: Final[int] = 65_536

# PCSR Finding 7b: security limits.
_MAX_BODY_SIZE: Final[int] = 10 * 1024 * 1024  # 10 MB
_MAX_HEADER_COUNT: Final[int] = 100
_MAX_HEADER_LINE_SIZE: Final[int] = 16384  # 16 KB

# Policy cache TTL in seconds.
_POLICY_CACHE_TTL: Final[float] = float(
    os.environ.get("EGRESS_POLICY_CACHE_TTL_SECONDS", "30")
)

# DynamoDB config table name.
_CONFIG_TABLE: Final[str] = os.environ.get("EGRESS_CONFIG_TABLE", "")


def _make_ssl_context() -> ssl.SSLContext:
    return ssl.create_default_context()


def _get_botocore_session() -> botocore.session.Session:
    return botocore.session.get_session()


class _ProxyConnection:
    """Handles one TCP connection from a MicroVM.

    PCSR Finding 7: all permit/deny decisions are delegated to ``Interceptor.intercept()``.
    This class is the I/O shell only — it reads the request, builds a typed request object,
    calls the Interceptor, and executes the outcome (forward, tunnel, or deny).
    """

    __slots__ = ("_interceptor", "_botocore_session", "_reader", "_writer")

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        botocore_session: botocore.session.Session,
        interceptor: Interceptor,
    ) -> None:
        self._reader = reader
        self._writer = writer
        self._botocore_session = botocore_session
        self._interceptor = interceptor

    async def handle(self) -> None:
        try:
            first_line = await asyncio.wait_for(
                self._reader.readline(), timeout=_IDLE_TIMEOUT
            )
            if not first_line:
                return

            line = first_line.decode("utf-8", errors="replace").strip()
            parts = line.split()
            if len(parts) < 3:
                self._send_error(400, "Bad Request")
                return

            method = parts[0].upper()
            target = parts[1]

            if method == "CONNECT":
                await self._handle_connect(target)
            else:
                await self._handle_forward(method, target)
        except TimeoutError:
            logger.debug("client idle timeout")
        except ConnectionResetError:
            logger.debug("connection reset by peer")
        except Exception:
            logger.exception("unhandled error on connection")
        finally:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:  # nosec B110
                pass

    # ------------------------------------------------------------------
    # CONNECT: build TunnelledConnection, let Interceptor decide
    # ------------------------------------------------------------------

    async def _handle_connect(self, target: str) -> None:
        # PCSR Finding 7b: bound the header drain.
        header_count = 0
        while True:
            header_line = await asyncio.wait_for(
                self._reader.readline(), timeout=_CONNECT_TIMEOUT
            )
            if header_line in (b"\r\n", b"\n", b""):
                break
            header_count += 1
            if header_count > _MAX_HEADER_COUNT or len(header_line) > _MAX_HEADER_LINE_SIZE:
                self._send_error(431, "Request Header Fields Too Large")
                return

        # Build typed request and let the Interceptor decide.
        request = TunnelledConnection(connect_target=target)
        outcome = self._interceptor.intercept(request)

        if isinstance(outcome, Denied):
            logger.info("DENY CONNECT %s (reason: %s)", target, outcome.reason.value)
            self._send_error(403, "Forbidden")
            return

        if isinstance(outcome, Tunnelled):
            host = outcome.upstream_host
            port = 443
            if ":" in target:
                _, _, port_str = target.partition(":")
                port = int(port_str) if port_str else 443

            logger.info("CONNECT %s:%d (set: %s)", host, port, outcome.destination_set)
            try:
                up_reader, up_writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=_CONNECT_TIMEOUT,
                )
            except Exception as exc:
                logger.warning("CONNECT upstream failed %s:%d: %s", host, port, exc)
                self._send_error(502, "Bad Gateway")
                return

            self._writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await self._writer.drain()
            await self._pipe(self._reader, up_writer, self._writer, up_reader)

            try:
                up_writer.close()
            except Exception:  # nosec B110
                pass
            return

        # Should not reach here — Interceptor returns Denied or Tunnelled for CONNECT.
        self._send_error(403, "Forbidden")

    # ------------------------------------------------------------------
    # Forward proxy: build TerminatedRequest, let Interceptor decide
    # ------------------------------------------------------------------

    async def _handle_forward(self, method: str, url: str) -> None:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        port = parsed.port or 443
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        # Read request headers with limits (PCSR Finding 7b).
        headers: dict[str, str] = {}
        content_length = 0
        header_count = 0
        while True:
            header_line = await asyncio.wait_for(
                self._reader.readline(), timeout=_CONNECT_TIMEOUT
            )
            if header_line in (b"\r\n", b"\n", b""):
                break
            header_count += 1
            if header_count > _MAX_HEADER_COUNT or len(header_line) > _MAX_HEADER_LINE_SIZE:
                self._send_error(431, "Request Header Fields Too Large")
                return
            decoded = header_line.decode("utf-8", errors="replace").strip()
            if ":" in decoded:
                name, _, value = decoded.partition(":")
                headers[name.strip()] = value.strip()
                if name.strip().lower() == "content-length":
                    content_length = int(value.strip())

        # PCSR Finding 7b: cap body size.
        if content_length > _MAX_BODY_SIZE:
            logger.info("DENY forward %s %s (body too large: %d)", method, host, content_length)
            self._send_error(413, "Payload Too Large")
            return

        body = b""
        if content_length > 0:
            body = await asyncio.wait_for(
                self._reader.readexactly(content_length), timeout=_IDLE_TIMEOUT
            )

        # Build typed request and let the Interceptor decide.
        host_header = headers.get("Host", headers.get("host", host))
        request = TerminatedRequest(
            server_name=host,
            host_header=host_header,
            method=method,
            path=path,
            headers=headers,
        )
        outcome = self._interceptor.intercept(request)

        if isinstance(outcome, Denied):
            logger.info("DENY forward %s %s%s (reason: %s)", method, host, path, outcome.reason.value)
            self._send_error(403, "Forbidden")
            return

        if isinstance(outcome, Forwarded):
            logger.info(
                "%s %s %s%s → %s (set: %s, injection: %s)",
                outcome.injection.value.upper(),
                method,
                host,
                path,
                outcome.upstream_host,
                outcome.destination_set,
                outcome.injection.value,
            )
            await self._execute_forward(method, outcome, port, path, body)
            return

        # Should not reach here for forward proxy requests.
        self._send_error(403, "Forbidden")

    async def _execute_forward(
        self,
        method: str,
        outcome: Forwarded,
        port: int,
        path: str,
        body: bytes,
    ) -> None:
        """Execute a permitted forward — connect upstream, send with injected headers, relay response."""
        upstream_host = outcome.upstream_host

        try:
            ssl_ctx = _make_ssl_context()
            up_reader, up_writer = await asyncio.wait_for(
                asyncio.open_connection(upstream_host, port, ssl=ssl_ctx),
                timeout=_CONNECT_TIMEOUT,
            )
        except Exception as exc:
            logger.error("upstream connect failed %s:%d: %s", upstream_host, port, exc)
            self._send_error(502, "Bad Gateway")
            return

        try:
            # The Interceptor already built the upstream headers with injection applied
            # and sandbox auth headers stripped. If this is SigV4 (Tier 1), we still need
            # to do the actual signing with the body, since the Interceptor only provides
            # the Authorization value without body awareness.
            if outcome.injection == Injection.RESIGN_AS_TASK_ROLE:
                # Re-sign with full body for SigV4
                await self._resign_and_forward(method, upstream_host, port, path, outcome.upstream_headers, body, up_reader, up_writer)
            else:
                # Tier 2 or other: headers are ready, just forward
                up_writer.write(f"{method} {path} HTTP/1.1\r\n".encode())
                for hdr_name, hdr_value in outcome.upstream_headers.items():
                    up_writer.write(f"{hdr_name}: {hdr_value}\r\n".encode())
                up_writer.write(b"\r\n")
                if body:
                    up_writer.write(body)
                await up_writer.drain()

                # Relay response, stripping configured headers
                await self._relay_response(up_reader, outcome.strip_response_headers)
        except Exception:
            logger.exception("error forwarding to %s", upstream_host)
        finally:
            try:
                up_writer.close()
            except Exception:  # nosec B110
                pass

    async def _resign_and_forward(
        self,
        method: str,
        upstream_host: str,
        port: int,
        path: str,
        base_headers: dict[str, str] | object,
        body: bytes,
        up_reader: asyncio.StreamReader,
        up_writer: asyncio.StreamWriter,
    ) -> None:
        """Tier 1: full SigV4 re-signing with the body included in the signature."""
        url = f"https://{upstream_host}{path}"

        # Start from the Interceptor's upstream headers (sandbox auth already stripped)
        clean = dict(base_headers) if isinstance(base_headers, dict) else {}
        clean["Host"] = upstream_host

        region = upstream_host.split(".")[1] if "." in upstream_host else "us-east-1"

        credentials = self._botocore_session.get_credentials()
        if credentials is None:
            logger.error("no credentials available for re-signing")
            self._send_error(502, "Bad Gateway")
            return
        frozen = credentials.get_frozen_credentials()

        # Determine service from host (e.g. bedrock-runtime → bedrock)
        service = upstream_host.split(".")[0].split("-")[0] if "." in upstream_host else "bedrock"

        aws_request = botocore.awsrequest.AWSRequest(
            method=method, url=url, headers=clean, data=body
        )
        signer = botocore.auth.SigV4Auth(frozen, service, region)
        signer.add_auth(aws_request)

        up_writer.write(f"{method} {path} HTTP/1.1\r\n".encode())
        for hdr_name, hdr_value in aws_request.headers.items():
            up_writer.write(f"{hdr_name}: {hdr_value}\r\n".encode())
        up_writer.write(b"\r\n")
        if body:
            up_writer.write(body)
        await up_writer.drain()

        # Relay response (no header stripping for Tier 1 — Bedrock responses are safe)
        await self._relay_response(up_reader, frozenset())

    async def _relay_response(
        self,
        up_reader: asyncio.StreamReader,
        strip_headers: frozenset[str],
    ) -> None:
        """Read upstream response and forward to the Sandbox, stripping configured headers."""
        status_line = await asyncio.wait_for(
            up_reader.readline(), timeout=_IDLE_TIMEOUT
        )
        self._writer.write(status_line)

        resp_content_length = -1
        chunked = False
        while True:
            resp_hdr = await asyncio.wait_for(
                up_reader.readline(), timeout=_CONNECT_TIMEOUT
            )
            # Strip configured response headers
            if strip_headers:
                hdr_lower = resp_hdr.decode("utf-8", errors="replace").strip().lower()
                hdr_name_lower = hdr_lower.split(":", 1)[0] if ":" in hdr_lower else ""
                if hdr_name_lower in strip_headers:
                    continue

            self._writer.write(resp_hdr)
            if resp_hdr in (b"\r\n", b"\n"):
                break
            lower = resp_hdr.decode("utf-8", errors="replace").strip().lower()
            if lower.startswith("content-length:"):
                resp_content_length = int(lower.split(":", 1)[1].strip())
            elif lower.startswith("transfer-encoding:") and "chunked" in lower:
                chunked = True
        await self._writer.drain()

        if chunked:
            await self._forward_chunked(up_reader)
        elif resp_content_length > 0:
            remaining = resp_content_length
            while remaining > 0:
                chunk = await asyncio.wait_for(
                    up_reader.read(min(remaining, _PIPE_BUFFER)),
                    timeout=_IDLE_TIMEOUT,
                )
                if not chunk:
                    break
                self._writer.write(chunk)
                remaining -= len(chunk)
                await self._writer.drain()
        elif resp_content_length == 0:
            pass
        else:
            while True:
                chunk = await asyncio.wait_for(
                    up_reader.read(_PIPE_BUFFER), timeout=_IDLE_TIMEOUT
                )
                if not chunk:
                    break
                self._writer.write(chunk)
                await self._writer.drain()

    async def _forward_chunked(self, up_reader: asyncio.StreamReader) -> None:
        while True:
            size_line = await asyncio.wait_for(
                up_reader.readline(), timeout=_IDLE_TIMEOUT
            )
            self._writer.write(size_line)
            await self._writer.drain()

            size_str = size_line.decode("utf-8", errors="replace").strip()
            chunk_size = int(size_str.split(";")[0], 16)
            if chunk_size == 0:
                trailer = await asyncio.wait_for(
                    up_reader.readline(), timeout=_CONNECT_TIMEOUT
                )
                self._writer.write(trailer)
                await self._writer.drain()
                break

            data = await asyncio.wait_for(
                up_reader.readexactly(chunk_size), timeout=_IDLE_TIMEOUT
            )
            self._writer.write(data)
            crlf = await asyncio.wait_for(
                up_reader.readexactly(2), timeout=_CONNECT_TIMEOUT
            )
            self._writer.write(crlf)
            await self._writer.drain()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _send_error(self, code: int, message: str) -> None:
        body = f"{code} {message}\r\n".encode()
        self._writer.write(
            f"HTTP/1.1 {code} {message}\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Content-Type: text/plain\r\n"
            f"\r\n".encode()
        )
        self._writer.write(body)

    @staticmethod
    async def _pipe(
        r1: asyncio.StreamReader,
        w1: asyncio.StreamWriter,
        w2: asyncio.StreamWriter,
        r2: asyncio.StreamReader,
    ) -> None:
        async def _forward(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                while True:
                    data = await asyncio.wait_for(
                        reader.read(_PIPE_BUFFER), timeout=_IDLE_TIMEOUT
                    )
                    if not data:
                        break
                    writer.write(data)
                    await writer.drain()
            except (TimeoutError, ConnectionResetError, BrokenPipeError, OSError):
                pass

        await asyncio.gather(
            _forward(r1, w1),
            _forward(r2, w2),
            return_exceptions=True,
        )


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------


def _build_interceptor() -> Interceptor:
    """Construct the Interceptor with DDB-backed policy, botocore signer, and SM tokens."""
    source = DDBPolicySource(table_name=_CONFIG_TABLE, cache_ttl=_POLICY_CACHE_TTL)
    # CachedPolicyReader has its own TTL; DDBPolicySource also caches the raw DDB read.
    # Use the same TTL for both so revocation latency is bounded by a single number.
    cache_ttl = min(_POLICY_CACHE_TTL, 30.0)
    reader = CachedPolicyReader(
        source=source,
        settings=PolicyCacheSettings(cache_ttl_seconds=cache_ttl),
    )
    signer = BotocoreSigner()
    tokens = SecretsManagerTokens()
    settings = InterceptionSettings.build()
    return Interceptor(reader=reader, settings=settings, signer=signer, tokens=tokens)


async def _run_server() -> None:
    session = _get_botocore_session()
    interceptor = _build_interceptor()
    # Force initial policy load.
    interceptor._reader.policy()

    async def _on_connect(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        conn = _ProxyConnection(reader, writer, session, interceptor)
        await conn.handle()

    server = await asyncio.start_server(_on_connect, "0.0.0.0", LISTEN_PORT)  # nosec B104
    addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
    logger.info("egress proxy listening on %s (policy from DDB table: %s)", addrs, _CONFIG_TABLE)

    async with server:
        await server.serve_forever()


def main() -> None:
    asyncio.run(_run_server())


if __name__ == "__main__":
    main()
