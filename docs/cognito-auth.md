<!-- kiro-classification: public -->

# Cognito Integration Guide

The sandbox ships with a **Lambda authorizer** using bearer tokens for multi-tenant
authentication. For production deployments, replace it with a **Cognito JWT authorizer**
for native JWT validation, user management, federation, and MFA.

## What changes

| Component | Current (Lambda authorizer) | Target (Cognito JWT) |
|-----------|---------------------------|---------------------|
| Auth type | Bearer token → Lambda function → tenantId | JWT → API Gateway JWT authorizer → tenantId |
| Token source | Hardcoded in authorizer code | Cognito User Pool issues JWTs |
| Tenant mapping | Token lookup table in Lambda | JWT `custom:tenantId` claim or `sub` |
| User management | Manual (add tokens to Lambda) | Cognito hosted UI, federation, MFA |
| Token refresh | None (static tokens) | Cognito refresh tokens (automatic) |
| Per-request cost | Lambda invocation (~$0.20/1M) | Zero (API Gateway validates JWT natively) |

## How to migrate

### 1. Create a Cognito User Pool

```bash
aws cognito-idp create-user-pool \
  --pool-name sandbox-users \
  --schema Name=custom:tenantId,AttributeDataType=String,Mutable=true \
  --auto-verified-attributes email \
  --policies 'PasswordPolicy={MinimumLength=12,RequireUppercase=true,RequireLowercase=true,RequireNumbers=true,RequireSymbols=true}'
```

### 2. Create an App Client

```bash
aws cognito-idp create-user-pool-client \
  --user-pool-id <pool-id> \
  --client-name sandbox-client \
  --no-generate-secret \
  --explicit-auth-flows ALLOW_USER_SRP_AUTH ALLOW_REFRESH_TOKEN_AUTH \
  --supported-identity-providers COGNITO
```

### 3. Replace the Lambda authorizer in ControlPlaneStack

In the CDK code, replace the Lambda authorizer with a JWT authorizer:

```python
from aws_cdk import aws_apigatewayv2 as apigwv2

jwt_authorizer = apigwv2.HttpJwtAuthorizer(
    "CognitoAuth",
    jwt_issuer=f"https://cognito-idp.{region}.amazonaws.com/{user_pool_id}",
    jwt_audience=[app_client_id],
)

# Apply to the HTTP API
api.add_routes(
    path="/sessions",
    methods=[apigwv2.HttpMethod.POST],
    authorizer=jwt_authorizer,
    integration=api_handler_integration,
)
```

### 4. Update tenant resolution

In `control_plane/tenancy.py`, update `tenant_of()` to read the tenant ID from
JWT claims instead of the Lambda authorizer context:

```python
def tenant_of(event: dict) -> str:
    """Extract tenantId from the authenticated request."""
    # JWT authorizer: claims are in requestContext.authorizer.jwt.claims
    jwt_claims = (
        event.get("requestContext", {})
        .get("authorizer", {})
        .get("jwt", {})
        .get("claims", {})
    )
    if jwt_claims:
        return jwt_claims.get("custom:tenantId", jwt_claims.get("sub", "operator"))

    # Lambda authorizer fallback (development)
    lambda_ctx = event.get("requestContext", {}).get("authorizer", {}).get("lambda", {})
    return lambda_ctx.get("tenantId", "operator")
```

### 5. Update SDK auth

Replace `BearerAuth` with Cognito token acquisition:

```python
from agent_sandbox import SandboxClient

# Before: static bearer token
client = SandboxClient(api_url="...", token="demo-token-tenant-a")

# After: Cognito JWT (use boto3 cognito-idp or any OIDC library)
import boto3
cognito = boto3.client("cognito-idp")
auth = cognito.initiate_auth(
    ClientId="<app-client-id>",
    AuthFlow="USER_SRP_AUTH",
    AuthParameters={"USERNAME": "user@example.com", "SRP_A": "..."},
)
id_token = auth["AuthenticationResult"]["IdToken"]
client = SandboxClient(api_url="...", token=id_token)
```

## Coexistence

The Lambda authorizer and Cognito JWT authorizer can coexist:
- Use Cognito JWT on production routes
- Keep the Lambda authorizer on development/testing routes
- The `tenant_of()` function handles both (see step 4 above)

## When to migrate

- **Development/demo**: Lambda authorizer is fine. Zero setup, hardcoded tokens.
- **Production with < 10 users**: Lambda authorizer still works. Add tokens manually.
- **Production with user management needs**: Migrate to Cognito. You get: self-service
  signup, password reset, MFA, social federation (Google, SAML), and zero per-request
  Lambda cost.
