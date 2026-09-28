# kiro-classification: public
"""Demo driver: step registry and main entry point (R16.1, R16.9, R16.10).

Defines the ``DemoStep`` protocol, maintains a step registry, runs steps in dependency order,
and reports per-step success or failure.  On any step failure the Session is terminated and the
failing step is named (R16.9).  On success the wall-clock duration and estimated cost are
reported (R16.7).  The Session is terminated before exiting (R16.8).

``main()`` is the entry point invoked by ``python -m demo``.
"""

from __future__ import annotations

import argparse
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

from demo.client import ControlPlaneClient

__all__ = ["DemoContext", "DemoStep", "StepRegistry", "main"]


# ---------------------------------------------------------------------------
# Step protocol and context
# ---------------------------------------------------------------------------

class StepCallable(Protocol):
    """The signature every step must satisfy."""

    def __call__(self, ctx: DemoContext) -> dict[str, Any]: ...


@dataclass
class DemoContext:
    """Mutable context threaded through every step.

    Holds the API client, the Sandbox client (once a Session is created), timing
    accumulators, and the Session identifier needed for teardown.
    """

    client: ControlPlaneClient
    region: str
    egress_endpoint: str | None = None
    session_id: str | None = None
    connection: dict[str, Any] | None = None
    sandbox_client: Any = None  # SandboxClient, set after creation
    start_time: float = field(default_factory=time.monotonic)
    active_seconds: float = 0.0
    suspended_seconds: float = 0.0
    step_results: dict[str, dict[str, Any]] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class DemoStep:
    """One registered demonstration step.

    Parameters
    ----------
    name:
        A human-readable name shown in the report.
    callable:
        A function ``(DemoContext) -> dict[str, Any]`` returning the step outcome.
    dependencies:
        Names of steps that must have succeeded first.  Ordering is the registry's.
    """

    name: str
    callable: StepCallable
    dependencies: tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# Step registry
# ---------------------------------------------------------------------------

class StepRegistry:
    """Ordered collection of ``DemoStep`` instances."""

    def __init__(self) -> None:
        self._steps: list[DemoStep] = []

    def register(self, step: DemoStep) -> None:
        """Add a step.  Dependencies must already be registered."""
        known = {s.name for s in self._steps}
        for dep in step.dependencies:
            if dep not in known:
                raise ValueError(
                    f"Step {step.name!r} depends on {dep!r}, which is not registered"
                )
        self._steps.append(step)

    @property
    def steps(self) -> tuple[DemoStep, ...]:
        return tuple(self._steps)


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def _terminate_session(ctx: DemoContext) -> None:
    """Best-effort termination — never raises (R16.8, R16.9)."""
    if ctx.session_id is None:
        return
    try:
        ctx.client.terminate_session(ctx.session_id)
    except Exception as exc:  # noqa: BLE001
        print(f"  [warning] Session termination failed: {exc}", file=sys.stderr)


def run_steps(registry: StepRegistry, ctx: DemoContext) -> bool:
    """Execute every step in order.  Return ``True`` iff all succeeded.

    On the first failure, terminates the Session (R16.9) and returns ``False``.
    """
    for step in registry.steps:
        print(f"\n{'='*60}")
        print(f"Step: {step.name}")
        print(f"{'='*60}")
        try:
            result = step.callable(ctx)
            ctx.step_results[step.name] = result
            _print_result(step.name, result, success=True)
        except Exception as exc:  # noqa: BLE001
            print(f"\n  FAILED: {step.name}")
            print(f"  Reason: {exc}")
            _terminate_session(ctx)
            return False
    return True


def _print_result(name: str, result: dict[str, Any], *, success: bool) -> None:
    tag = "OK" if success else "FAIL"
    print(f"  [{tag}] {name}")
    for key, value in result.items():
        display = value if isinstance(value, str) else repr(value)
        # Truncate long values for readability
        if isinstance(display, str) and len(display) > 200:
            display = display[:200] + "..."
        print(f"    {key}: {display}")


# ---------------------------------------------------------------------------
# CLI entry point (R16.10)
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m demo",
        description=(
            "Run the end-to-end demonstration against a deployed IaC_Package (R16.10).  "
            "Provisions a Session, exercises the Sandbox, and reports results."
        ),
    )
    parser.add_argument(
        "--api-url",
        required=True,
        help="Root URL of the deployed Control_Plane HTTP API.",
    )
    parser.add_argument(
        "--region",
        required=True,
        help="AWS Region the API is deployed in.",
    )
    parser.add_argument(
        "--egress-endpoint",
        default=None,
        help=(
            "DNS name of the internal NLB fronting the Egress_Controller proxy fleet.  "
            "Required for the Bedrock invocation step (R16.2).  Typically the NLB's DNS "
            "name from the deployed EgressStack."
        ),
    )
    parser.add_argument(
        "--deployment-profile",
        default="single-tenant",
        choices=["single-tenant", "multi-tenant"],
        help=(
            "Deployment profile. When 'multi-tenant', registers the tenant isolation "
            "demo step that exercises cross-tenant partition confinement."
        ),
    )
    parser.add_argument(
        "--token",
        default=None,
        help=(
            "Bearer token for multi-tenant deployments that use a Lambda authorizer.  "
            "When set, API calls use Authorization: Bearer <token> instead of SigV4."
        ),
    )
    parser.add_argument(
        "--persistence",
        action="store_true",
        default=False,
        help=(
            "Enable persistent storage verification steps.  When set, a Session is "
            "created with persistence=True and the /mnt/workspace mount is tested.  "
            "Requires the deployment to include S3 Files context parameters."
        ),
    )
    return parser


def build_registry(
    *,
    deployment_profile: str = "single-tenant",
    persistence: bool = False,
) -> StepRegistry:
    """Assemble the full step registry for the main workload path.

    Imports are deferred so that ``--help`` does not require AWS credentials.
    When ``deployment_profile`` is ``"multi-tenant"``, the tenant isolation step is registered.
    When ``persistence`` is ``True``, persistent storage verification steps are registered.
    """
    from demo.steps.egress_block import register_egress_steps
    from demo.steps.reporting import register_reporting_steps
    from demo.steps.suspend_resume import register_suspend_resume_steps
    from demo.steps.tenant_isolation import register_tenant_isolation_steps
    from demo.steps.workload import register_workload_steps

    registry = StepRegistry()
    register_workload_steps(registry, persistence=persistence)
    register_suspend_resume_steps(registry)
    register_egress_steps(registry)
    if persistence:
        from demo.steps.persistence import register_persistence_steps
        register_persistence_steps(registry)
    register_tenant_isolation_steps(registry, deployment_profile=deployment_profile)
    register_reporting_steps(registry)
    return registry


def main(argv: list[str] | None = None) -> None:
    """CLI entry point — one documented command against a deployed IaC_Package (R16.10)."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    client = ControlPlaneClient(api_url=args.api_url, region=args.region, token=args.token)
    ctx = DemoContext(client=client, region=args.region, egress_endpoint=args.egress_endpoint)
    registry = build_registry(deployment_profile=args.deployment_profile, persistence=args.persistence)

    print("AWS Serverless Agent Sandbox — End-to-End Demonstration")
    print(f"API: {args.api_url}")
    print(f"Region: {args.region}")
    if args.persistence:
        print("Persistence: enabled (S3 Files)")

    success = run_steps(registry, ctx)

    if success:
        print(f"\n{'='*60}")
        print("All steps completed successfully.")
        print(f"{'='*60}")
        sys.exit(0)
    else:
        print(f"\n{'='*60}")
        print("Demonstration FAILED — see above for the failing step.")
        print(f"{'='*60}")
        sys.exit(1)
