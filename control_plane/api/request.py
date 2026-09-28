# kiro-classification: public
"""Reading one API Gateway HTTP API invocation, and refusing one that proves nothing (R6.3).

Two things are read from an invocation and they come from different places for a reason.

**The identity comes from the request context, never from the request.** Every route carries the
`AWS_IAM` authorizer (:data:`~control_plane.api.routes.AUTHORIZATION_TYPE`), so a request without a
valid SigV4 signature is rejected by API Gateway before this code runs. What reaches a handler is
the identity the service verified, in `requestContext.authorizer.iam`. This module reads it from
there and from nowhere else: not from a header, not from a query string, not from the body. The
`multi-tenant` profile's Tenant attribute is read from the authorizer context map for the same
reason — it is written by the gateway from configuration the deployment controls, and no caller can
set it.

**The handler still fails closed.** The authorizer has already run, so a check here is
belt-and-braces rather than the boundary. It is worth its four lines anyway, because the failure it
covers is a misconfiguration rather than an attack: a route synthesised without the authorizer, or
an invocation arriving by some path that bypassed it, would otherwise be served with whatever
identity the code could scrape together. Instead there is no identity to scrape — an invocation
with no verified caller is refused with the fixed
:data:`~control_plane.api.errors.FORBIDDEN_RESPONSE`, and there is no default principal anywhere in
this module for it to fall back to.

The contrast with the Sandbox_Runtime is deliberate and is settled in the design rather than left
to each component. `runtime/app.py` authenticates nothing, because it is untrusted code's
neighbour and a check it performed could be bypassed by the code it was meant to constrain. The
Control_Plane is the trusted side of that boundary and the sole issuer of the credential the
runtime's endpoint checks, so this is where identity is established.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
from collections.abc import Mapping
from typing import Any, Final

from control_plane.api.errors import MalformedRequest, UnauthenticatedRequest
from control_plane.tenancy import (
    AuthenticatedPrincipal,
    TenantIdentifierError,
    VerifiedCallerIdentity,
    tenant_of,
)

__all__ = [
    "AUTHORIZER_KEY",
    "CALLER_IDENTITY_FIELD",
    "IAM_AUTHORIZER_KEY",
    "REQUEST_CONTEXT_KEY",
    "TENANT_ATTRIBUTE_FIELD",
    "TENANT_CLAIM_PATH_VAR",
    "principal_for",
    "request_body",
    "request_method_and_path",
    "verified_caller_identity",
]

REQUEST_CONTEXT_KEY: Final = "requestContext"

#: The authorizer context map of an HTTP API invocation. Populated by API Gateway from the route's
#: authorizer; not reachable from a request.
AUTHORIZER_KEY: Final = "authorizer"

#: The sub-map an `AWS_IAM`-authorized route carries. Its presence is the handler's evidence that
#: the authorizer ran.
IAM_AUTHORIZER_KEY: Final = "iam"

#: The verified caller's ARN, inside the `iam` sub-map.
CALLER_IDENTITY_FIELD: Final = "userArn"

#: Where the `multi-tenant` profile's Tenant attribute is read from, on the authorizer context map
#: rather than on the service-populated `iam` sub-map, because it is a value the deployment's
#: authorizer configuration supplies. Absent under `single-tenant`, where
#: :class:`~control_plane.tenancy.FixedTenantResolver` never reads it, and where a caller therefore
#: cannot influence the Tenant even in principle. Under `multi-tenant` an invocation whose verified
#: identity carries no Tenant attribute is refused rather than defaulted: handing an unattributed
#: caller any Tenant would hand them somebody's partition.
TENANT_ATTRIBUTE_FIELD: Final = "tenantId"

#: The default tenant field name, used when no custom claim path is configured.
_DEFAULT_TENANT_FIELD: Final = "tenantId"

#: Environment variable for a configurable dot-separated path into the authorizer context from which
#: the Tenant identifier is read. When set, this path is walked after the default lookups (IAM,
#: Lambda authorizer, JWT claims) as a fallback.
TENANT_CLAIM_PATH_VAR: Final = "TENANT_CLAIM_PATH"


def _mapping(source: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    """Return a nested mapping, or an empty one when it is absent or the wrong shape."""
    value = source.get(key)
    return value if isinstance(value, Mapping) else {}


def verified_caller_identity(event: Mapping[str, Any]) -> VerifiedCallerIdentity:
    """Extract the caller identity from either AWS_IAM or Lambda/JWT authorizer context.

    Checks IAM authorizer first (single-tenant default), then falls back to Lambda authorizer
    context and JWT claims for multi-tenant deployments that use a Lambda or JWT authorizer.

    Raises :class:`~control_plane.api.errors.UnauthenticatedRequest` when the invocation carries no
    verified caller identity from any supported authorizer type.
    """
    request_context = _mapping(event, REQUEST_CONTEXT_KEY)
    authorizer = _mapping(request_context, AUTHORIZER_KEY)

    # Try IAM authorizer first (single-tenant default).
    iam_context = _mapping(authorizer, IAM_AUTHORIZER_KEY)
    caller_identity = iam_context.get(CALLER_IDENTITY_FIELD)

    if not caller_identity:
        # Try Lambda authorizer context — caller identity from principalId or a configured field.
        # Lambda authorizer returns context at requestContext.authorizer.lambda.*
        lambda_context = _mapping(authorizer, "lambda")
        caller_identity = lambda_context.get("principalId") or lambda_context.get(
            "userArn"
        )

        if not caller_identity:
            # JWT authorizer: caller from claims.
            jwt_claims = _mapping(_mapping(authorizer, "jwt"), "claims")
            caller_identity = jwt_claims.get("sub") or jwt_claims.get("email")

    if not isinstance(caller_identity, str) or not caller_identity:
        raise UnauthenticatedRequest(
            "invocation carries no verified caller identity from the authorizer"
        )

    # Extract tenant ID — check multiple paths.
    tenant_id: str | None = None

    # 1. Flat authorizer context (Lambda authorizer puts it here).
    flat_value = authorizer.get(_DEFAULT_TENANT_FIELD)
    if isinstance(flat_value, str) and flat_value:
        tenant_id = flat_value

    # 2. Lambda authorizer context.
    if not tenant_id:
        lambda_context = _mapping(authorizer, "lambda")
        lambda_value = lambda_context.get(_DEFAULT_TENANT_FIELD)
        if isinstance(lambda_value, str) and lambda_value:
            tenant_id = lambda_value

    # 3. JWT claims (Cognito puts custom attributes as custom:tenantId).
    if not tenant_id:
        jwt_claims = _mapping(_mapping(authorizer, "jwt"), "claims")
        jwt_value = jwt_claims.get("custom:tenantId") or jwt_claims.get(
            _DEFAULT_TENANT_FIELD
        )
        if isinstance(jwt_value, str) and jwt_value:
            tenant_id = jwt_value

    # 4. Configurable path from environment.
    custom_path = os.environ.get(TENANT_CLAIM_PATH_VAR)
    if custom_path and not tenant_id:
        # Walk the dot-separated path through the authorizer context.
        value: Any = authorizer
        for segment in custom_path.split("."):
            if isinstance(value, Mapping):
                value = value.get(segment)
            else:
                value = None
                break
        if isinstance(value, str) and value:
            tenant_id = value

    tenant_id = tenant_id if isinstance(tenant_id, str) and tenant_id else None

    try:
        return VerifiedCallerIdentity(
            caller_identity=caller_identity, tenant_id=tenant_id or None
        )
    except TenantIdentifierError as exc:
        raise UnauthenticatedRequest(str(exc)) from exc


def principal_for(event: Mapping[str, Any]) -> AuthenticatedPrincipal:
    """Resolve the authenticated principal, and with it the one Tenant this request may address.

    :func:`~control_plane.tenancy.tenant_of` is the single call by which the Tenant is learned, and
    its argument is the verified identity and nothing else, under both Deployment_Profiles. A
    resolver failure — a `multi-tenant` principal with no Tenant attribute, a Tenant identifier
    that could not become part of a key — becomes the fixed authorization refusal, because there is
    no Tenant to scope the request to and therefore no request to serve.
    """
    identity = verified_caller_identity(event)
    try:
        return AuthenticatedPrincipal(
            caller_identity=identity.caller_identity, tenant_id=tenant_of(identity)
        )
    except TenantIdentifierError as exc:
        raise UnauthenticatedRequest(str(exc)) from exc


def request_method_and_path(event: Mapping[str, Any]) -> tuple[str, str]:
    """Return the HTTP method and raw path of a payload-format-2.0 invocation.

    `rawPath` rather than `path`, and the method from `requestContext.http`, which is where format
    2.0 puts them. An invocation missing either yields empty strings and therefore matches no
    route, which the dispatcher answers with the fixed not-found response.
    """
    http = _mapping(_mapping(event, REQUEST_CONTEXT_KEY), "http")
    method = http.get("method")
    raw_path = event.get("rawPath")
    return (
        method if isinstance(method, str) else "",
        raw_path if isinstance(raw_path, str) else "",
    )


def request_body(event: Mapping[str, Any]) -> Mapping[str, Any]:
    """Decode the request body into a JSON object, `{}` when there is none.

    An absent body is an empty object rather than an error: `CreateSession` with every field
    defaulted is a valid request (R6.4), and the suspend, resume and terminate operations carry no
    body at all. A body that is present but is not a JSON object is a `400`, because there is no
    field for an operation to read and no useful default to invent — that is a malformed request
    rather than an admission failure, so it is distinct from the validation task 6.2 adds.
    """
    raw = event.get("body")
    if raw is None or raw == "":
        return {}

    if isinstance(raw, (bytes, bytearray)):
        encoded = bytes(raw)
    elif isinstance(raw, str):
        if event.get("isBase64Encoded") is True:
            try:
                encoded = base64.b64decode(raw, validate=True)
            except (binascii.Error, ValueError) as exc:
                raise MalformedRequest("request body is not valid base64") from exc
        else:
            encoded = raw.encode("utf-8")
    else:
        raise MalformedRequest("request body is not a string")

    try:
        decoded = json.loads(encoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MalformedRequest("request body is not valid JSON") from exc
    if not isinstance(decoded, dict):
        raise MalformedRequest("request body is not a JSON object")
    return decoded
