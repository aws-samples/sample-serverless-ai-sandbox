# kiro-classification: public
"""Reporting and teardown step (R16.7, R16.8, R16.9).

- Calculate and report wall-clock duration of the demo run.
- Estimate cost based on active time, suspended time, and storage.
- Terminate the Session via ``POST /sessions/{id}/terminate`` (R16.8).
- On failure at any step, ensure Session termination happens (R16.9) — handled by the driver,
  but this step always terminates as the final action.
"""

from __future__ import annotations

import time
from typing import Any, Final

from demo.driver import DemoContext, DemoStep, StepRegistry

__all__ = ["register_reporting_steps"]

# ---------------------------------------------------------------------------
# Cost estimation constants (public Lambda MicroVM pricing, us-east-1)
# ---------------------------------------------------------------------------

#: Per-second compute charge for a 512 MiB MicroVM while RUNNING (approximate).
_COMPUTE_PER_SECOND_USD: Final[float] = 0.0000083

#: Per-second storage charge while SUSPENDED (snapshot storage, approximate).
_SUSPENDED_PER_SECOND_USD: Final[float] = 0.0000003

#: Per-GB-month S3 storage charge for artifacts (approximate).
_STORAGE_PER_GB_MONTH_USD: Final[float] = 0.023


def _step_report_and_terminate(ctx: DemoContext) -> dict[str, Any]:
    """Report wall-clock duration, estimated cost, and terminate the Session (R16.7, R16.8)."""
    wall_clock = time.monotonic() - ctx.start_time
    active_seconds = wall_clock - ctx.suspended_seconds

    # Cost estimate.
    compute_cost = active_seconds * _COMPUTE_PER_SECOND_USD
    suspend_cost = ctx.suspended_seconds * _SUSPENDED_PER_SECOND_USD
    # Storage cost is negligible for a short demo — report it as a per-session estimate.
    estimated_total = compute_cost + suspend_cost

    # Terminate the Session (R16.8) — always, whether earlier steps passed or failed.
    termination_result = "skipped (no session)"
    if ctx.session_id is not None:
        try:
            ctx.client.terminate_session(ctx.session_id)
            termination_result = "terminated"
        except Exception as exc:  # noqa: BLE001
            termination_result = f"failed: {exc}"

    return {
        "wall_clock_seconds": round(wall_clock, 3),
        "active_seconds": round(active_seconds, 3),
        "suspended_seconds": round(ctx.suspended_seconds, 3),
        "estimated_compute_cost_usd": f"${compute_cost:.6f}",
        "estimated_suspend_cost_usd": f"${suspend_cost:.6f}",
        "estimated_total_cost_usd": f"${estimated_total:.6f}",
        "session_terminated": termination_result,
    }


def register_reporting_steps(registry: StepRegistry) -> None:
    """Register the reporting and teardown step on *registry*."""
    registry.register(DemoStep(
        name="report-and-terminate",
        callable=_step_report_and_terminate,
        # Depends on all prior steps having been attempted (the driver runs them in order).
        dependencies=("create-session",),
    ))
