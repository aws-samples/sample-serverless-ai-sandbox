# kiro-classification: public
"""Authentication utilities for the Control Plane API.

Two modes:
- **SigV4**: signs requests with the caller's current AWS credentials via ``botocore``.
- **Bearer token**: attaches ``Authorization: Bearer <token>`` for multi-tenant deployments
  that use a Lambda authorizer instead of ``AWS_IAM``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Final, Protocol

__all__ = ["Auth", "SigV4Auth", "BearerAuth"]

#: Service name used for SigV4 signing against API Gateway.
_SERVICE_NAME: Final = "execute-api"


class Auth(Protocol):
    """Authentication strategy applied to outgoing Control Plane requests."""

    def apply(self, method: str, url: str, headers: dict[str, str], body: bytes | None) -> dict[str, str]:
        """Return a new headers dict with authentication applied."""
        ...  # pragma: no cover


@dataclass(frozen=True, slots=True)
class SigV4Auth:
    """Signs requests using AWS SigV4 via ``botocore``.

    Parameters
    ----------
    region:
        AWS region the API is deployed in (e.g. ``us-east-1``).
    """

    region: str

    def apply(self, method: str, url: str, headers: dict[str, str], body: bytes | None) -> dict[str, str]:
        """Sign the request and return headers with SigV4 auth attached."""
        import botocore.auth  # type: ignore[import-untyped]
        import botocore.awsrequest  # type: ignore[import-untyped]
        import botocore.session  # type: ignore[import-untyped]

        aws_request = botocore.awsrequest.AWSRequest(
            method=method, url=url, data=body, headers=headers,
        )

        session = botocore.session.get_session()
        credentials = session.get_credentials()
        if credentials is None:
            raise RuntimeError(
                "No AWS credentials found. Set AWS_PROFILE or credential environment variables."
            )
        signer = botocore.auth.SigV4Auth(
            credentials.get_frozen_credentials(), _SERVICE_NAME, self.region,
        )
        signer.add_auth(aws_request)
        return dict(aws_request.headers)


@dataclass(frozen=True, slots=True)
class BearerAuth:
    """Attaches a bearer token for multi-tenant deployments.

    Parameters
    ----------
    token:
        The bearer token string.
    """

    token: str

    def apply(self, method: str, url: str, headers: dict[str, str], body: bytes | None) -> dict[str, str]:
        """Return headers with the Authorization bearer header attached."""
        result = dict(headers)
        result["Authorization"] = f"Bearer {self.token}"
        return result
