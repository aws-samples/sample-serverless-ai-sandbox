# kiro-classification: public
"""Lambda authorizer for the Control Plane API (multi-tenant mode).

Validates bearer tokens against the ``TENANT_TOKEN_MAP`` environment variable.
If the token maps to a known tenant, the request is authorized with that tenant's
identity. All other requests are rejected.

For single-tenant deployments, the CDK stack sets API Gateway routes to ``AWS_IAM``
and this authorizer is not deployed (PCSR Finding 3).

API Gateway HTTP API Lambda authorizer payload format 2.0:
- Input: { "headers": { "authorization": "Bearer <token>" }, ... }
- Output: { "isAuthorized": true/false, "context": { "tenantId": "...", "principalId": "..." } }
"""

from __future__ import annotations

import hmac
import json
import logging
import os
from typing import Any, Final

logger = logging.getLogger()
logger.setLevel(logging.INFO)

#: Environment variable carrying a JSON token-to-tenant mapping.
_TOKEN_MAP_VAR: Final = "TENANT_TOKEN_MAP"

def _load_token_map() -> dict[str, str]:
    """Load the token-to-tenant mapping from the environment.

    PCSR Finding 2: absent or invalid TENANT_TOKEN_MAP denies all requests.
    No hardcoded fallback tokens.
    """
    raw = os.environ.get(_TOKEN_MAP_VAR)
    if not raw:
        logger.warning("TENANT_TOKEN_MAP not set — all bearer tokens will be rejected")
        return {}
    try:
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            logger.error("TENANT_TOKEN_MAP is not a JSON object — rejecting all tokens")
            return {}
        return parsed
    except json.JSONDecodeError:
        logger.error("TENANT_TOKEN_MAP is not valid JSON — rejecting all tokens")
        return {}


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Lambda authorizer handler (payload format 2.0, simple response).

    This authorizer handles bearer token authentication only (multi-tenant mode).
    For single-tenant / IAM-only deployments, the CDK stack sets routes to AWS_IAM
    and this authorizer is not deployed (PCSR Finding 3).
    """
    token_map = _load_token_map()

    headers = event.get("headers", {})
    auth_header = headers.get("authorization", "")

    # Bearer token → multi-tenant: validate against the token-tenant mapping.
    if auth_header.lower().startswith("bearer "):
        token = auth_header[7:].strip()
        # PCSR Finding 2: constant-time comparison to prevent timing attacks.
        tenant_id = None
        for map_token, map_tenant in token_map.items():
            if hmac.compare_digest(map_token, token):
                tenant_id = map_tenant
                break

        if not tenant_id:
            logger.info("Bearer token not recognized")
            return {"isAuthorized": False}

        logger.info("Authorized tenant: %s", tenant_id)
        return {
            "isAuthorized": True,
            "context": {
                "tenantId": tenant_id,
                "principalId": f"tenant:{tenant_id}",
            },
        }

    # PCSR Finding 1: no valid credential → reject.
    # Path 2 (accountId check) removed — accountId is the API owner's account ID,
    # populated on every invocation regardless of caller authentication.
    logger.info("No valid bearer token found")
    return {"isAuthorized": False}
