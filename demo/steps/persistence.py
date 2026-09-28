# kiro-classification: public
"""Persistence verification steps.

When S3 Files persistent storage is configured, these steps verify:
1. The /mnt/workspace mount point is present and writable.
2. Data written to /mnt/workspace survives a suspend/resume cycle.

These steps are registered conditionally — only when ``--persistence`` is passed
or when the deployment has S3 Files configured (auto-detected from CloudFormation).

Note: /mnt/workspace is an NFS mount backed by S3 Files.  The protocol-level
``fs.write``/``fs.read`` commands are scoped to /tmp, so persistence steps use
``execute`` (shell commands) for /mnt/workspace I/O.
"""

from __future__ import annotations

import time
from typing import Any

from demo.driver import DemoContext, DemoStep, StepRegistry

__all__ = ["register_persistence_steps"]

_MOUNT_PATH: str = "/mnt/workspace"
_TEST_FILE: str = "/mnt/workspace/persistence_test.txt"
_TEST_DATA: str = "persistence-round-trip-ok"


def _step_verify_mount(ctx: DemoContext) -> dict[str, Any]:
    """Verify /mnt/workspace is mounted and writable."""
    assert ctx.sandbox_client is not None

    # Check mount point exists via stat
    result = ctx.sandbox_client.execute(
        ["sh", "-c", f"stat -f {_MOUNT_PATH} 2>&1 && echo MOUNT_OK || echo MOUNT_MISSING"],
        timeout_seconds=10,
    )
    detail = result if isinstance(result, str) else str(result)
    if "MOUNT_MISSING" in detail:
        raise AssertionError(
            f"{_MOUNT_PATH} is not mounted. "
            "Ensure deployment includes S3 Files context parameters."
        )

    # Write and remove a probe to confirm writable
    probe = ctx.sandbox_client.execute(
        ["sh", "-c", f"echo probe > {_MOUNT_PATH}/.probe && rm {_MOUNT_PATH}/.probe && echo WRITABLE"],
        timeout_seconds=10,
    )
    probe_out = probe if isinstance(probe, str) else str(probe)
    if "WRITABLE" not in probe_out:
        raise AssertionError(f"{_MOUNT_PATH} is not writable: {probe_out}")

    return {
        "mount_path": _MOUNT_PATH,
        "status": "mounted and writable",
        "detail": detail[:200] if len(detail) > 200 else detail,
    }


def _exec_write(ctx: DemoContext, path: str, data: str) -> None:
    """Write data to a file inside the sandbox via execute."""
    result = ctx.sandbox_client.execute(
        ["sh", "-c", f"echo -n '{data}' > {path}"],
        timeout_seconds=10,
    )
    out = result if isinstance(result, dict) else {}
    exit_code = out.get("field_1", -1) if isinstance(out, dict) else -1
    if exit_code != 0:
        stderr = out.get("field_3", "") if isinstance(out, dict) else str(result)
        raise AssertionError(f"Write to {path} failed: {stderr}")


def _exec_read(ctx: DemoContext, path: str) -> str:
    """Read file content from the sandbox via execute."""
    result = ctx.sandbox_client.execute(
        ["cat", path],
        timeout_seconds=10,
    )
    if isinstance(result, dict):
        exit_code = result.get("field_1", -1)
        if exit_code != 0:
            stderr = result.get("field_3", "")
            raise AssertionError(f"Read from {path} failed: {stderr}")
        return result.get("field_2", "")
    return str(result)


def _step_persist_across_suspend(ctx: DemoContext) -> dict[str, Any]:
    """Write to /mnt/workspace, suspend, resume, read back, assert match."""
    assert ctx.sandbox_client is not None
    assert ctx.session_id is not None

    # 1. Write test data via shell
    _exec_write(ctx, _TEST_FILE, _TEST_DATA)

    # 2. Verify written
    pre_read = _exec_read(ctx, _TEST_FILE)
    if pre_read != _TEST_DATA:
        raise AssertionError(
            f"Pre-suspend read mismatch: wrote {_TEST_DATA!r}, read {pre_read!r}"
        )

    # 3. Suspend
    suspend_t0 = time.monotonic()
    ctx.client.suspend_session(ctx.session_id)
    suspend_elapsed = time.monotonic() - suspend_t0
    ctx.suspended_seconds += suspend_elapsed

    time.sleep(2.0)  # nosemgrep: arbitrary-sleep

    # 4. Resume
    resume_t0 = time.monotonic()
    ctx.client.resume_session(ctx.session_id)
    resume_elapsed = time.monotonic() - resume_t0

    # 5. Refresh connection after resume
    from demo.sandbox import SandboxClient

    refreshed = ctx.client.refresh_connection(ctx.session_id)
    connection = refreshed.get("connection", ctx.connection)
    if connection is not None:
        ctx.connection = connection
        ctx.sandbox_client = SandboxClient.from_connection(connection)

    # 6. Read back and compare
    post_read = _exec_read(ctx, _TEST_FILE)
    if post_read != _TEST_DATA:
        raise AssertionError(
            f"Persistence failed: wrote {_TEST_DATA!r}, "
            f"read back {post_read!r} after suspend/resume"
        )

    # 7. Clean up
    ctx.sandbox_client.execute(
        ["rm", "-f", _TEST_FILE],
        timeout_seconds=5,
    )

    return {
        "file_path": _TEST_FILE,
        "bytes_written": len(_TEST_DATA),
        "content_matches_after_resume": True,
        "suspend_seconds": round(suspend_elapsed, 3),
        "resume_seconds": round(resume_elapsed, 3),
    }


def register_persistence_steps(registry: StepRegistry) -> None:
    """Register persistence verification steps on *registry*."""
    registry.register(DemoStep(
        name="persistence-verify-mount",
        callable=_step_verify_mount,
        dependencies=("create-session",),
    ))
    registry.register(DemoStep(
        name="persistence-survive-suspend",
        callable=_step_persist_across_suspend,
        dependencies=("persistence-verify-mount",),
    ))
