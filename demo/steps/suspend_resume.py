# kiro-classification: public
"""Suspend and resume step (R16.5).

Writes a file to the Sandbox filesystem, suspends the Session, resumes it, reads the file
back, and asserts equality.
"""

from __future__ import annotations

import time
from typing import Any

from demo.driver import DemoContext, DemoStep, StepRegistry

__all__ = ["register_suspend_resume_steps"]

#: The content written before suspend, read back after resume, and compared byte-for-byte.
_TEST_CONTENT: bytes = b"suspend-resume-test: filesystem state must survive"

#: Where the test file lives inside the Sandbox.
_TEST_PATH: str = "/tmp/suspend_resume_test.txt"  # nosec B108


def _step_suspend_resume(ctx: DemoContext) -> dict[str, Any]:
    """Write → suspend → resume → read → assert equality (R16.5)."""
    assert ctx.sandbox_client is not None
    assert ctx.session_id is not None

    # 1. Write a file before suspension.
    ctx.sandbox_client.write_file(_TEST_PATH, _TEST_CONTENT)

    # 2. Suspend the Session.
    suspend_start = time.monotonic()
    ctx.client.suspend_session(ctx.session_id)
    suspend_elapsed = time.monotonic() - suspend_start
    ctx.suspended_seconds += suspend_elapsed

    # Give the Sandbox a moment to fully suspend.
    time.sleep(2.0)  # nosemgrep: arbitrary-sleep — polling loop by design

    # 3. Resume the Session.
    resume_start = time.monotonic()
    ctx.client.resume_session(ctx.session_id)
    resume_elapsed = time.monotonic() - resume_start

    # 4. Refresh the connection credential after resume and rebuild the sandbox client.
    from demo.sandbox import SandboxClient

    refreshed = ctx.client.refresh_connection(ctx.session_id)
    connection = refreshed.get("connection", ctx.connection)
    if connection is not None:
        ctx.connection = connection
        ctx.sandbox_client = SandboxClient.from_connection(connection)

    # 5. Read the file back and assert equality.
    read_back = ctx.sandbox_client.read_file(_TEST_PATH)
    if read_back != _TEST_CONTENT:
        raise AssertionError(
            f"File content mismatch after suspend/resume: "
            f"wrote {len(_TEST_CONTENT)} bytes, read {len(read_back)} bytes"
        )

    return {
        "file_path": _TEST_PATH,
        "bytes_written": len(_TEST_CONTENT),
        "bytes_read": len(read_back),
        "content_matches": True,
        "suspend_seconds": round(suspend_elapsed, 3),
        "resume_seconds": round(resume_elapsed, 3),
    }


def register_suspend_resume_steps(registry: StepRegistry) -> None:
    """Register the suspend/resume step on *registry*."""
    registry.register(DemoStep(
        name="suspend-resume",
        callable=_step_suspend_resume,
        dependencies=("create-session",),
    ))
