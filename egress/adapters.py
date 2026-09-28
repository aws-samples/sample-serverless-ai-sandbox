# kiro-classification: public
"""Adapters bridging the deployed DDB policy format and AWS SDK to the Interceptor protocols.

PCSR Finding 7: these adapters connect the I/O layer (server.py) to the pure decision
logic (interception.py) without changing the DDB policy format or the Interceptor API.

Three adapters:
- DDBPolicySource: reads flat DDB format → returns EgressPolicy
- BotocoreSigner: implements UpstreamSigner via botocore SigV4Auth
- SecretsManagerTokens: implements UpstreamTokens via boto3 Secrets Manager
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Final

import boto3
import botocore.auth
import botocore.awsrequest
import botocore.session

from egress.interception import UpstreamCredentialUnavailable, UpstreamSigner, UpstreamTokens
from egress.policy import EgressPolicy, PolicyDocumentError, Tier
from egress.reader import PolicySource, PolicyUnavailable

__all__ = [
    "BotocoreSigner",
    "DDBPolicySource",
    "SecretsManagerTokens",
]

logger = logging.getLogger("egress-proxy.adapters")

# ---------------------------------------------------------------------------
# DDB → EgressPolicy adapter
# ---------------------------------------------------------------------------

# Headers from the Sandbox that must not survive re-signing.
_STRIPPED_AUTH_HEADERS: Final[frozenset[str]] = frozenset(
    {"authorization", "x-amz-date", "x-amz-content-sha256", "x-amz-security-token"}
)


class DDBPolicySource:
    """Reads the flat DDB policy format and converts it to an EgressPolicy.

    The DDB format uses:
        {"policyVersion": N, "bedrock": {"tier": 1, "hosts": [...]},
         "tier2": [...], "allowed": [...], "packages": {"hosts": [...]}, ...}

    This adapter transforms it to the Interceptor's format:
        {"policyVersion": N, "defaultAction": "deny",
         "destinationSets": {"bedrock": {"tier": 1, "entries": [...]}, ...}}
    """

    def __init__(self, table_name: str, cache_ttl: float = 30.0) -> None:
        self._table_name = table_name
        self._cache_ttl = cache_ttl
        self._ddb = boto3.resource("dynamodb").Table(table_name) if table_name else None
        self._cached_raw: dict[str, Any] | None = None
        self._read_at: float = 0.0

    def read(self) -> EgressPolicy:
        """Read the DDB policy and convert to EgressPolicy.

        Raises:
            PolicyUnavailable: DDB read failed or policy is empty.
        """
        raw = self._read_raw()
        document = self._transform(raw)
        try:
            return EgressPolicy.from_document(document)
        except PolicyDocumentError as exc:
            raise PolicyUnavailable(f"policy document invalid: {exc}") from exc

    def _read_raw(self) -> dict[str, Any]:
        """Read the flat policy from DDB with caching."""
        now = time.monotonic()
        if self._cached_raw is not None and (now - self._read_at) < self._cache_ttl:
            return self._cached_raw
        if not self._ddb:
            raise PolicyUnavailable("no DDB table configured")
        try:
            resp = self._ddb.get_item(Key={"pk": "EGRESS_POLICY"})
            item = resp.get("Item")
            if not item:
                raise PolicyUnavailable("no EGRESS_POLICY item in table")
            policy_str = item.get("policy", "{}")
            raw = json.loads(policy_str) if isinstance(policy_str, str) else policy_str
            self._cached_raw = raw
            self._read_at = time.monotonic()
            return raw
        except PolicyUnavailable:
            raise
        except Exception as exc:
            raise PolicyUnavailable(f"DDB read failed: {exc}") from exc

    @staticmethod
    def _transform(raw: dict[str, Any]) -> dict[str, Any]:
        """Convert flat DDB format to the EgressPolicy document schema.

        Maps:
        - bedrock.hosts → destinationSets.bedrock (tier 1, each host as an entry with alias)
        - tier2 list → destinationSets.<alias> (tier 2, with upstreamHost, injectHeader, secretArn)
        - allowed list → destinationSets.allowed (tier 3, each as a CONNECT tunnel entry)
        - packages.hosts, system.hosts etc. → destinationSets.<name> (tier 3)
        """
        version = raw.get("policyVersion", 1)
        destination_sets: dict[str, Any] = {}

        # Bedrock → Tier 1 (SigV4 re-signing)
        bedrock = raw.get("bedrock", {})
        if isinstance(bedrock, dict):
            hosts = bedrock.get("hosts", [])
            if hosts:
                entries = []
                for host in hosts:
                    if isinstance(host, str):
                        # Tier 1: alias = host, upstreamHost = host, signAs from service name
                        # e.g. bedrock-runtime.us-east-1.amazonaws.com → signAs: "bedrock"
                        service = host.split(".")[0].split("-")[0] if "." in host else "bedrock"
                        entries.append({"alias": host, "upstreamHost": host, "signAs": service})
                if entries:
                    destination_sets["bedrock"] = {
                        "tier": 1,
                        "entries": entries,
                    }

        # Tier 2 entries (token injection)
        tier2 = raw.get("tier2", [])
        if isinstance(tier2, list):
            for entry in tier2:
                if isinstance(entry, dict) and entry.get("alias") and entry.get("injectHeader") and entry.get("secretArn"):
                    alias = entry["alias"]
                    set_entry: dict[str, Any] = {"alias": alias}
                    if entry.get("upstreamHost"):
                        set_entry["upstreamHost"] = entry["upstreamHost"]
                    if entry.get("injectHeader"):
                        set_entry["injectHeader"] = entry["injectHeader"]
                    if entry.get("secretArn"):
                        set_entry["secretArn"] = entry["secretArn"]
                    if entry.get("stripResponseHeaders"):
                        set_entry["stripResponseHeaders"] = entry["stripResponseHeaders"]
                    # Each Tier 2 alias gets its own destination set
                    safe_name = alias.replace(".", "_")
                    destination_sets[f"tier2_{safe_name}"] = {
                        "tier": 2,
                        **set_entry,
                    }

        # Named host lists (packages, system, etc.) → Tier 3
        skip_keys = {"policyVersion", "defaultAction", "bedrock", "tier2", "allowed"}
        for key, value in raw.items():
            if key in skip_keys:
                continue
            if isinstance(value, dict) and "hosts" in value:
                hosts = value["hosts"]
                if isinstance(hosts, list) and hosts:
                    entries = []
                    for host in hosts:
                        if isinstance(host, str):
                            entries.append({"upstreamHost": host})
                    if entries:
                        destination_sets[key] = {"tier": 3, "entries": entries}

        # Flat allowed list → Tier 3
        allowed = raw.get("allowed", [])
        if isinstance(allowed, list) and allowed:
            entries = []
            for item in allowed:
                host = item.get("host", item) if isinstance(item, dict) else item
                if isinstance(host, str):
                    entries.append({"upstreamHost": host})
            if entries:
                destination_sets["allowed"] = {"tier": 3, "entries": entries}

        return {
            "policyVersion": max(version, 1),
            "defaultAction": "deny",
            "destinationSets": destination_sets,
        }


# ---------------------------------------------------------------------------
# UpstreamSigner: botocore SigV4
# ---------------------------------------------------------------------------


class BotocoreSigner:
    """Implements UpstreamSigner by re-signing with botocore SigV4Auth."""

    def __init__(self, session: botocore.session.Session | None = None) -> None:
        self._session = session or botocore.session.get_session()

    def authorization(
        self, *, sign_as: str, upstream_host: str, method: str, path: str
    ) -> str:
        """Re-sign and return the Authorization header value.

        Raises:
            UpstreamCredentialUnavailable: credentials not available.
        """
        credentials = self._session.get_credentials()
        if credentials is None:
            raise UpstreamCredentialUnavailable("no IAM credentials available for SigV4 re-signing")
        frozen = credentials.get_frozen_credentials()

        # Derive the service from the host (e.g. bedrock-runtime.us-east-1.amazonaws.com → bedrock)
        service = sign_as or "bedrock"
        region = "us-east-1"
        parts = upstream_host.split(".")
        if len(parts) >= 3:
            region = parts[1]

        url = f"https://{upstream_host}{path}"
        request = botocore.awsrequest.AWSRequest(method=method, url=url, headers={"Host": upstream_host})
        signer = botocore.auth.SigV4Auth(frozen, service, region)
        signer.add_auth(request)
        auth_value = request.headers.get("Authorization", "")
        if not auth_value:
            raise UpstreamCredentialUnavailable("SigV4 signing produced no Authorization header")
        return auth_value


# ---------------------------------------------------------------------------
# UpstreamTokens: Secrets Manager
# ---------------------------------------------------------------------------

_SECRET_CACHE_TTL: Final[float] = 300.0  # 5 minutes


class SecretsManagerTokens:
    """Implements UpstreamTokens by reading secrets from AWS Secrets Manager with caching."""

    def __init__(self) -> None:
        self._client = boto3.client("secretsmanager")
        self._cache: dict[str, tuple[str, float]] = {}

    def token(self, secret_arn: str) -> str:
        """Read and cache the secret value.

        Raises:
            UpstreamCredentialUnavailable: secret could not be read.
        """
        now = time.monotonic()
        cached = self._cache.get(secret_arn)
        if cached and (now - cached[1]) < _SECRET_CACHE_TTL:
            return cached[0]
        try:
            resp = self._client.get_secret_value(SecretId=secret_arn)
            value = resp.get("SecretString", "")
            if not value:
                raise UpstreamCredentialUnavailable(f"secret {secret_arn} has no value")
            self._cache[secret_arn] = (value, now)
            return value
        except UpstreamCredentialUnavailable:
            raise
        except Exception as exc:
            raise UpstreamCredentialUnavailable(f"failed to read secret: {exc}") from exc
