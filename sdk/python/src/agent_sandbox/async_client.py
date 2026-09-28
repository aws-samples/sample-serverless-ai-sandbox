# kiro-classification: public
"""Async Python Client SDK for the AWS Serverless Agent Sandbox.

Quick start::

    import asyncio
    from agent_sandbox.async_client import AsyncSandboxClient

    async def main():
        client = AsyncSandboxClient(
            api_url="https://xxx.execute-api.us-east-1.amazonaws.com",
            region="us-east-1",
        )
        session = await client.create_session(persistence=True)
        await session.wait_ready()
        result = await session.execute(["echo", "hello"])
        print(result.stdout)
        await session.terminate()
        await client.close()

    asyncio.run(main())
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any

import httpx

from agent_sandbox.auth import Auth, SigV4Auth, BearerAuth
from agent_sandbox.sandbox import (
    CommandResult,
    FileEntry,
    FileInfo,
    SandboxConnection,
)


_POLL_INTERVAL: float = 3.0


@dataclass
class AsyncSandboxSession:
    """Async wrapper around a sandbox session."""

    session_id: str
    api_url: str
    lifecycle_state: str = "UNKNOWN"
    _auth: Auth | None = None
    _session_data: dict[str, Any] | None = None
    _http_client: httpx.AsyncClient | None = None
    _sandbox: SandboxConnection | None = None

    @property
    def connection(self) -> dict[str, Any] | None:
        if self._session_data:
            return self._session_data.get("connection")
        return None

    @property
    def is_ready(self) -> bool:
        return self.lifecycle_state == "RUNNING" and self.connection is not None

    async def refresh(self) -> None:
        data = await self._cp_request("GET", f"/sessions/{self.session_id}")
        self._session_data = data
        self.lifecycle_state = data.get("lifecycleState", "UNKNOWN")

    async def wait_ready(self, *, timeout: float = 120, poll_interval: float = _POLL_INTERVAL) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            await self.refresh()
            if self.is_ready:  # nosemgrep: is-function-without-parentheses
                return
            if self.lifecycle_state in ("TERMINATED", "FAILED"):
                raise RuntimeError(f"Session {self.session_id} is {self.lifecycle_state}")
            await asyncio.sleep(poll_interval)
        raise TimeoutError(f"Session {self.session_id} not ready after {timeout}s")

    async def suspend(self) -> dict[str, Any]:
        return await self._cp_request("POST", f"/sessions/{self.session_id}/suspend")

    async def resume(self) -> dict[str, Any]:
        return await self._cp_request("POST", f"/sessions/{self.session_id}/resume")

    async def terminate(self) -> dict[str, Any]:
        return await self._cp_request("POST", f"/sessions/{self.session_id}/terminate")

    async def refresh_connection(self) -> dict[str, Any]:
        result = await self._cp_request("POST", f"/sessions/{self.session_id}/connection")
        self._session_data = result
        return result

    # --- Sandbox operations (delegate to sync SandboxConnection in a thread) ---

    def _get_sandbox(self) -> SandboxConnection:
        if self._sandbox is not None:
            return self._sandbox
        conn = self.connection
        if not conn:
            raise RuntimeError(
                f"Session {self.session_id} has no connection. Call wait_ready() first."
            )
        self._sandbox = SandboxConnection(
            base_url=conn["baseUrl"],
            auth_header_name=conn["authHeaderName"],
            auth_header_value=conn["authHeaderValue"],
        )
        return self._sandbox

    async def execute(
        self,
        command: list[str] | str,
        *,
        cwd: str = "/tmp",  # nosec B108
        env: dict[str, str] | None = None,
        timeout_seconds: int = 60,
    ) -> CommandResult:
        sandbox = self._get_sandbox()
        if isinstance(command, str):
            command = ["sh", "-c", command]
        return await asyncio.to_thread(
            sandbox.execute, command, cwd=cwd, env=env or {}, timeout_seconds=timeout_seconds
        )

    async def write_file(self, path: str, content: str | bytes, *, mode: int = 0o644) -> None:
        sandbox = self._get_sandbox()
        # Convert string to bytes for the CBOR protocol
        if isinstance(content, str):
            content = content.encode("utf-8")
        await asyncio.to_thread(sandbox.write_file, path, content, mode=mode)

    async def read_file(self, path: str) -> str:
        sandbox = self._get_sandbox()
        return await asyncio.to_thread(sandbox.read_file, path)

    async def read_file_bytes(self, path: str) -> bytes:
        sandbox = self._get_sandbox()
        return await asyncio.to_thread(sandbox.read_file_bytes, path)

    async def list_files(self, path: str = "/tmp") -> list[FileEntry]:  # nosec B108
        sandbox = self._get_sandbox()
        return await asyncio.to_thread(sandbox.list_files, path)

    async def delete_file(self, path: str, *, recursive: bool = False) -> None:
        sandbox = self._get_sandbox()
        await asyncio.to_thread(sandbox.delete_file, path, recursive=recursive)

    # --- Control plane requests ---

    async def _cp_request(
        self, method: str, path: str, body: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        import json as _json
        url = f"{self.api_url.rstrip('/')}{path}"
        body_bytes = _json.dumps(body).encode() if body else None
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._auth:
            headers = self._auth.apply(method, url, headers, body_bytes)
        client = self._http_client or httpx.AsyncClient(timeout=30)
        if method == "GET":
            resp = await client.get(url, headers=headers)
        else:
            resp = await client.post(url, content=body_bytes, headers=headers)
        resp.raise_for_status()
        return resp.json()


class AsyncSandboxClient:
    """Async client for the AWS Serverless Agent Sandbox.

    Usage::

        async with AsyncSandboxClient(api_url="...", region="us-east-1") as client:
            session = await client.create_session(persistence=True)
            await session.wait_ready()
            result = await session.execute(["echo", "hello"])
    """

    def __init__(
        self,
        *,
        api_url: str,
        region: str = "us-east-1",
        token: str | None = None,
    ) -> None:
        self.api_url = api_url.rstrip("/")
        self._region = region
        self._auth: Auth = BearerAuth(token) if token else SigV4Auth(region)
        self._http_client = httpx.AsyncClient(timeout=30)

    async def create_session(
        self,
        *,
        max_duration_seconds: int = 3600,
        idle_seconds: int = 300,
        suspended_seconds: int = 600,
        auto_resume: bool = True,
        persistence: bool = False,
        affinity_key: str = "",
    ) -> AsyncSandboxSession:
        body: dict[str, object] = {
            "maxDurationSeconds": max_duration_seconds,
            "idleSeconds": idle_seconds,
            "suspendedSeconds": suspended_seconds,
            "autoResume": auto_resume,
        }
        if persistence:
            body["persistence"] = True
        if affinity_key:
            body["affinityKey"] = affinity_key

        session = AsyncSandboxSession(
            session_id="",
            api_url=self.api_url,
            _auth=self._auth,
            _http_client=self._http_client,
        )
        data = await session._cp_request("POST", "/sessions", body)
        session.session_id = data.get("sessionId", "")
        session.lifecycle_state = data.get("lifecycleState", "UNKNOWN")
        session._session_data = data
        return session

    async def get_session(self, session_id: str) -> AsyncSandboxSession:
        session = AsyncSandboxSession(
            session_id=session_id,
            api_url=self.api_url,
            _auth=self._auth,
            _http_client=self._http_client,
        )
        await session.refresh()
        return session

    async def list_sessions(self) -> list[dict[str, Any]]:
        session = AsyncSandboxSession(
            session_id="",
            api_url=self.api_url,
            _auth=self._auth,
            _http_client=self._http_client,
        )
        data = await session._cp_request("GET", "/sessions")
        return data.get("sessions", [])

    async def close(self) -> None:
        if self._http_client:
            await self._http_client.aclose()

    async def __aenter__(self) -> AsyncSandboxClient:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()
