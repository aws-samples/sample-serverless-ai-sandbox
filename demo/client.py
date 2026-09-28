# kiro-classification: public
"""Lightweight SigV4-signing HTTP client for the Control_Plane API (R16.10).

A thin wrapper around ``urllib.request`` and ``botocore`` SigV4 signing.  This is NOT the
full Client_SDK (paused in Tier 3); it is the minimal surface the Demo_Application needs to
drive the eight Control_Plane operations against a deployed IaC_Package.

Every request is signed with the caller's current AWS credentials via ``botocore``.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Final
from urllib.parse import urljoin

import botocore.auth  # type: ignore[import-untyped]
import botocore.awsrequest  # type: ignore[import-untyped]
import botocore.session  # type: ignore[import-untyped]

__all__ = ["ControlPlaneClient"]

#: Service name used for SigV4 signing.
_SERVICE_NAME: Final = "execute-api"


@dataclass(frozen=True, slots=True)
class ControlPlaneClient:
    """A SigV4-signing HTTP client for the Control_Plane API.

    Parameters
    ----------
    api_url:
        The root URL of the deployed HTTP API (e.g. ``https://<id>.execute-api.<region>.amazonaws.com``).
    region:
        The AWS Region the API is deployed in.
    token:
        Optional bearer token for multi-tenant deployments that use a Lambda authorizer
        instead of ``AWS_IAM``.  When set, requests carry ``Authorization: Bearer <token>``
        instead of a SigV4 signature.
    """

    api_url: str
    region: str
    token: str | None = None

    # ------------------------------------------------------------------
    # The eight Control_Plane operations (R6.1)
    # ------------------------------------------------------------------

    def create_session(self, body: dict[str, Any]) -> dict[str, Any]:
        """``POST /sessions`` — create a Session (R16.1)."""
        return self._request("POST", "/sessions", body=body)

    def resolve_session(self, body: dict[str, Any]) -> dict[str, Any]:
        """``POST /sessions/resolve`` — get-or-create by Affinity_Key."""
        return self._request("POST", "/sessions/resolve", body=body)

    def get_session(self, session_id: str) -> dict[str, Any]:
        """``GET /sessions/{id}`` — inspect a Session."""
        return self._request("GET", f"/sessions/{session_id}")

    def list_sessions(self) -> dict[str, Any]:
        """``GET /sessions`` — list Sessions in the caller's Tenant partition."""
        return self._request("GET", "/sessions")

    def suspend_session(self, session_id: str) -> dict[str, Any]:
        """``POST /sessions/{id}/suspend`` — suspend a Session (R16.5)."""
        return self._request("POST", f"/sessions/{session_id}/suspend")

    def resume_session(self, session_id: str) -> dict[str, Any]:
        """``POST /sessions/{id}/resume`` — resume a Session (R16.5)."""
        return self._request("POST", f"/sessions/{session_id}/resume")

    def terminate_session(self, session_id: str) -> dict[str, Any]:
        """``POST /sessions/{id}/terminate`` — terminate a Session (R16.8)."""
        return self._request("POST", f"/sessions/{session_id}/terminate")

    def refresh_connection(self, session_id: str) -> dict[str, Any]:
        """``POST /sessions/{id}/connection`` — refresh the connection credential."""
        return self._request("POST", f"/sessions/{session_id}/connection")

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Send a signed or bearer-authenticated request and return the parsed JSON response."""
        url = urljoin(self.api_url.rstrip("/") + "/", path.lstrip("/"))
        data = json.dumps(body).encode() if body is not None else None
        headers: dict[str, str] = {"Content-Type": "application/json"} if data else {}

        if self.token is not None:
            # Bearer token mode — no SigV4, just the Authorization header.
            headers["Authorization"] = f"Bearer {self.token}"
        else:
            # SigV4 mode — sign with the caller's current AWS credentials.
            aws_request = botocore.awsrequest.AWSRequest(
                method=method, url=url, data=data, headers=headers
            )

            session = botocore.session.get_session()
            credentials = session.get_credentials()
            if credentials is None:
                raise RuntimeError("No AWS credentials found — set AWS_PROFILE or credential env vars")
            signer = botocore.auth.SigV4Auth(
                credentials.get_frozen_credentials(), _SERVICE_NAME, self.region
            )
            signer.add_auth(aws_request)
            headers = dict(aws_request.headers)

        # Transfer headers to a stdlib request.
        stdlib_request = urllib.request.Request(
            url,
            data=data,
            headers=headers,
            method=method,
        )

        try:
            with urllib.request.urlopen(stdlib_request) as response: # nosec B310 # nosemgrep: dynamic-urllib-use-detected
                return json.loads(response.read())  # type: ignore[no-any-return]
        except urllib.error.HTTPError as exc:
            response_body = exc.read().decode(errors="replace")
            raise RuntimeError(
                f"Control_Plane returned HTTP {exc.code} for {method} {path}: {response_body}"
            ) from exc
