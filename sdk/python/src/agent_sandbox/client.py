# kiro-classification: public
"""SandboxClient — the main entry point for the Python Client SDK.

Usage::

    from agent_sandbox import SandboxClient

    # SigV4 auth (default for single-tenant deployments)
    client = SandboxClient(
        api_url="https://xxx.execute-api.us-east-1.amazonaws.com",
        region="us-east-1",
    )

    # Bearer token auth (multi-tenant deployments)
    client = SandboxClient(
        api_url="https://xxx.execute-api.us-east-1.amazonaws.com",
        region="us-east-1",
        token="demo-token-tenant-a",
    )

    # Create a session and wait for the sandbox
    session = client.create_session(max_duration_seconds=3600)
    session.wait_ready(timeout=120)

    # Execute commands
    result = session.execute("echo hello world")
    print(result.stdout)  # "hello world\\n"

    # Context manager for automatic cleanup
    with client.create_session() as session:
        session.wait_ready()
        session.execute("echo managed")
    # Session terminated automatically
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin

import httpx

from agent_sandbox.auth import Auth, BearerAuth, SigV4Auth
from agent_sandbox.session import SandboxSession

__all__ = ["SandboxClient"]


@dataclass(slots=True)
class SandboxClient:
    """Client for the AWS Serverless Agent Sandbox.

    Creates and manages sandbox sessions. Each session wraps a Lambda MicroVM
    with command execution and file operations.

    Parameters
    ----------
    api_url:
        The root URL of the deployed Control Plane HTTP API
        (e.g. ``https://<id>.execute-api.<region>.amazonaws.com``).
    region:
        The AWS Region the API is deployed in.
    token:
        Optional bearer token for multi-tenant deployments. When set, requests
        use ``Authorization: Bearer <token>`` instead of SigV4.
    """

    api_url: str
    region: str
    token: str | None = None

    _auth: Auth = field(init=False, repr=False)
    _http_client: httpx.Client = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if self.token is not None:
            self._auth = BearerAuth(token=self.token)
        else:
            self._auth = SigV4Auth(region=self.region)

        self._http_client = httpx.Client(timeout=httpx.Timeout(30.0, read=120.0))

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    def create_session(
        self,
        *,
        max_duration_seconds: int = 3600,
        idle_seconds: int = 300,
        suspended_seconds: int = 600,
        auto_resume: bool = True,
        persistence: bool = False,
        affinity_key: str = "",
    ) -> SandboxSession:
        """Create a new sandbox session.

        The session is created asynchronously. Call :meth:`SandboxSession.wait_ready`
        to block until the sandbox is reachable.

        Parameters
        ----------
        max_duration_seconds:
            Maximum session duration (1–28800, default: 3600).
        idle_seconds:
            Seconds of inactivity before auto-suspend (default: 300).
        suspended_seconds:
            Maximum seconds in suspended state (default: 600).
        auto_resume:
            Whether to auto-resume on request to a suspended sandbox.
        persistence:
            Mount an S3 Files workspace at ``/mnt/workspace`` inside the sandbox.
            Files written there sync to S3 and persist across suspend/resume.
            Default: False (ephemeral ``/tmp`` only).
        affinity_key:
            Share a workspace across sessions. Sessions with the same
            ``(tenant, affinity_key)`` see the same ``/mnt/workspace`` contents.
            Requires ``persistence=True``. If omitted, each session gets an
            isolated workspace.

        Returns
        -------
        SandboxSession
            The session handle, which may not yet have a connection descriptor.
        """
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
        data = self._cp_request("POST", "/sessions", body=body)
        session_id = data.get("sessionId", "")
        return SandboxSession(
            session_id=session_id,
            api_url=self.api_url,
            auth=self._auth,
            session_data=data,
            http_client=self._http_client,
        )

    def resolve_session(
        self,
        affinity_key: str,
        *,
        max_duration_seconds: int = 3600,
        idle_seconds: int = 300,
        suspended_seconds: int = 600,
        auto_resume: bool = True,
    ) -> SandboxSession:
        """Get or create a session by affinity key.

        If a session already exists for this affinity key, it is returned.
        Otherwise a new session is created and bound to the key.

        Parameters
        ----------
        affinity_key:
            A caller-supplied stable identifier (e.g. conversation ID).
        max_duration_seconds:
            Maximum session duration for a newly created session.
        idle_seconds:
            Seconds of inactivity before auto-suspend.
        suspended_seconds:
            Maximum seconds in suspended state.
        auto_resume:
            Whether to auto-resume on request to a suspended sandbox.

        Returns
        -------
        SandboxSession
            The resolved or newly created session.
        """
        body: dict[str, Any] = {
            "affinityKey": affinity_key,
            "maxDurationSeconds": max_duration_seconds,
            "idleSeconds": idle_seconds,
            "suspendedSeconds": suspended_seconds,
            "autoResume": auto_resume,
        }
        data = self._cp_request("POST", "/sessions/resolve", body=body)
        session_id = data.get("sessionId", "")
        return SandboxSession(
            session_id=session_id,
            api_url=self.api_url,
            auth=self._auth,
            session_data=data,
            http_client=self._http_client,
        )

    def get_session(self, session_id: str) -> SandboxSession:
        """Get an existing session by its ID.

        Parameters
        ----------
        session_id:
            The session identifier.

        Returns
        -------
        SandboxSession
            The session handle with the current state.
        """
        data = self._cp_request("GET", f"/sessions/{session_id}")
        return SandboxSession(
            session_id=session_id,
            api_url=self.api_url,
            auth=self._auth,
            session_data=data,
            http_client=self._http_client,
        )

    def list_sessions(self) -> list[dict[str, Any]]:
        """List sessions in the caller's tenant partition.

        Returns
        -------
        list[dict[str, Any]]
            The session records.
        """
        data = self._cp_request("GET", "/sessions")
        return data.get("sessions", [data] if "sessionId" in data else [])

    # ------------------------------------------------------------------
    # Context manager and cleanup
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._http_client.close()

    def __enter__(self) -> SandboxClient:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _cp_request(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Send an authenticated request to the Control Plane API."""
        url = urljoin(self.api_url.rstrip("/") + "/", path.lstrip("/"))
        data = json.dumps(body).encode() if body is not None else None
        headers: dict[str, str] = {"Content-Type": "application/json"} if data else {}

        headers = self._auth.apply(method, url, headers, data)

        resp = self._http_client.request(method, url, content=data, headers=headers)
        resp.raise_for_status()
        return resp.json()  # type: ignore[no-any-return]
