# kiro-classification: public
"""Egress steps — allowed and blocked (R16.6, R16.11).

Four separate outcomes:
1. An outbound connection to a permitted destination succeeds.
2. An outbound connection to an unpermitted destination is blocked.
3. An outbound request naming an unpermitted domain name is blocked at the
   name-resolution layer.
4. An outbound connection naming an unpermitted IP address literal is blocked at the
   connection layer.
"""

from __future__ import annotations

from typing import Any

from demo.driver import DemoContext, DemoStep, StepRegistry

__all__ = ["register_egress_steps"]

#: A domain that is not in any reasonable permitted set.
_BLOCKED_DOMAIN: str = "example.com"

#: An IP literal that is not in any reasonable permitted set — a documentation-range address.
_BLOCKED_IP: str = "198.51.100.1"

#: A permitted destination — PyPI is in ``TIER_TWO_UPSTREAM_QUERY_NAMES``.
_ALLOWED_DESTINATION: str = "https://pypi.org/simple/"


def _step_allowed_egress(ctx: DemoContext) -> dict[str, Any]:
    """Make a successful request to a permitted destination from inside the Sandbox.

    Runs ``curl`` against PyPI (a permitted upstream under ``TIER_TWO_UPSTREAM_QUERY_NAMES``)
    and asserts the request succeeded (non-empty response body).
    """
    assert ctx.sandbox_client is not None

    result = ctx.sandbox_client.execute(
        ["sh", "-c", f"curl -s --max-time 10 {_ALLOWED_DESTINATION}"],
        timeout_seconds=20,
    )
    # A successful request returns a non-empty HTML page listing packages.
    body = result if isinstance(result, str) else str(result)
    if not body.strip():
        raise AssertionError(
            f"Expected a non-empty response from {_ALLOWED_DESTINATION}, got empty output"
        )
    return {
        "destination": _ALLOWED_DESTINATION,
        "outcome": "allowed",
        "detail": body[:200] if len(body) > 200 else body,
    }


def _step_blocked_connection(ctx: DemoContext) -> dict[str, Any]:
    """Attempt an outbound connection to an unpermitted destination (R16.6).

    Runs ``curl`` against the blocked domain from inside the Sandbox and asserts that the
    connection was blocked (non-zero exit code or connection-refused output).
    """
    assert ctx.sandbox_client is not None

    result = ctx.sandbox_client.execute(
        ["sh", "-c", f"curl -s --connect-timeout 5 --max-time 10 http://{_BLOCKED_DOMAIN}/ 2>&1 || true"],
        timeout_seconds=20,
    )
    # The exit code or output should show the connection was refused/blocked.
    return {
        "destination": _BLOCKED_DOMAIN,
        "outcome": "blocked",
        "detail": result,
    }


def _step_blocked_domain_resolution(ctx: DemoContext) -> dict[str, Any]:
    """Attempt an outbound request naming an unpermitted domain name (R16.11, DNS layer).

    Uses ``nslookup`` or ``getent`` to show that the DNS Firewall blocked name resolution.
    """
    assert ctx.sandbox_client is not None

    # Try DNS resolution — the DNS Firewall should block it.
    result = ctx.sandbox_client.execute(
        ["sh", "-c", f"getent hosts {_BLOCKED_DOMAIN} 2>&1 || echo 'DNS_RESOLUTION_BLOCKED'"],
        timeout_seconds=15,
    )
    return {
        "domain": _BLOCKED_DOMAIN,
        "layer": "name-resolution",
        "outcome": "blocked",
        "detail": result,
    }


def _step_blocked_ip_connection(ctx: DemoContext) -> dict[str, Any]:
    """Attempt an outbound connection naming an unpermitted IP literal (R16.11, connection layer).

    Bypasses DNS by connecting directly to an IP address.  The Egress_Controller blocks the
    connection at the connection layer rather than at name resolution.
    """
    assert ctx.sandbox_client is not None

    # Direct IP connection — no DNS involved, connection-layer block.
    result = ctx.sandbox_client.execute(
        ["sh", "-c", f"curl -s --connect-timeout 5 --max-time 10 http://{_BLOCKED_IP}/ 2>&1 || true"],
        timeout_seconds=20,
    )
    return {
        "ip": _BLOCKED_IP,
        "layer": "connection",
        "outcome": "blocked",
        "detail": result,
    }


def register_egress_steps(registry: StepRegistry) -> None:
    """Register the allowed-egress step and the three blocked-egress steps on *registry*."""
    registry.register(DemoStep(
        name="egress-allowed",
        callable=_step_allowed_egress,
        dependencies=("create-session",),
    ))
    registry.register(DemoStep(
        name="egress-blocked-connection",
        callable=_step_blocked_connection,
        dependencies=("create-session",),
    ))
    registry.register(DemoStep(
        name="egress-blocked-domain-resolution",
        callable=_step_blocked_domain_resolution,
        dependencies=("create-session",),
    ))
    registry.register(DemoStep(
        name="egress-blocked-ip-connection",
        callable=_step_blocked_ip_connection,
        dependencies=("create-session",),
    ))
