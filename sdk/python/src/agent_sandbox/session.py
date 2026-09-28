# kiro-classification: public
"""SandboxSession — represents one sandbox session with lifecycle and sandbox operations.

A session wraps the Control Plane session record and, once the sandbox is ready,
provides command execution and file operations over the Sandbox Protocol.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Final
from urllib.parse import urljoin

import httpx

from agent_sandbox.auth import Auth
from agent_sandbox.git import GitOperations, GitStatus
from agent_sandbox.sandbox import (
    CommandResult,
    FileEntry,
    FileEvent,
    FileInfo,
    Metrics,
    ProcessHandle,
    PtySession,
    SandboxConnection,
)

__all__ = ["SandboxSession", "CommandResult", "FileEntry", "FileEvent", "FileInfo", "Metrics", "ProcessHandle", "PtySession"]

#: Default polling interval when waiting for a sandbox to become ready.
_POLL_INTERVAL: Final = 2.0


@dataclass(slots=True)
class SandboxSession:
    """A single sandbox session with lifecycle and sandbox operations.

    Typically created via :meth:`SandboxClient.create_session` rather than directly.

    Parameters
    ----------
    session_id:
        The Control Plane session identifier.
    api_url:
        The Control Plane API root URL.
    auth:
        The authentication strategy for Control Plane requests.
    session_data:
        The full session record from the Control Plane.
    http_client:
        An ``httpx.Client`` for connection pooling.
    """

    session_id: str
    api_url: str
    auth: Auth
    session_data: dict[str, Any] = field(default_factory=dict)
    http_client: httpx.Client | None = None

    _sandbox: SandboxConnection | None = field(default=None, init=False, repr=False)

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def lifecycle_state(self) -> str:
        """The current lifecycle state (e.g. ``RUNNING``, ``SUSPENDED``)."""
        return self.session_data.get("lifecycleState", "UNKNOWN")

    @property
    def connection(self) -> dict[str, Any] | None:
        """The connection descriptor, or ``None`` if the sandbox isn't ready yet."""
        return self.session_data.get("connection")

    @property
    def is_ready(self) -> bool:
        """Whether the sandbox has a connection descriptor (i.e. is reachable)."""
        return self.connection is not None

    # ------------------------------------------------------------------
    # Lifecycle operations (Control Plane)
    # ------------------------------------------------------------------

    def refresh(self) -> None:
        """Fetch the latest session state from the Control Plane."""
        self.session_data = self._cp_request("GET", f"/sessions/{self.session_id}")

    def wait_ready(self, *, timeout: float = 120, poll_interval: float = _POLL_INTERVAL) -> None:
        """Block until the sandbox has a connection descriptor.

        Parameters
        ----------
        timeout:
            Maximum seconds to wait before raising ``TimeoutError``.
        poll_interval:
            Seconds between polls (default: 2).

        Raises
        ------
        TimeoutError
            If the sandbox is not ready within *timeout* seconds.
        RuntimeError
            If the session enters a terminal state (``TERMINATED`` or ``FAILED``).
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.refresh()
            if self.is_ready:  # nosemgrep: is-function-without-parentheses — @property
                return
            state = self.lifecycle_state
            if state in ("TERMINATED", "FAILED"):
                raise RuntimeError(
                    f"Session {self.session_id} entered terminal state {state!r} "
                    f"while waiting for the sandbox to become ready."
                )
            time.sleep(poll_interval)  # nosemgrep: arbitrary-sleep — polling loop by design

        raise TimeoutError(
            f"Sandbox for session {self.session_id} was not ready within {timeout}s. "
            f"Last state: {self.lifecycle_state}"
        )

    def suspend(self) -> dict[str, Any]:
        """Suspend the session, preserving memory and disk state."""
        result = self._cp_request("POST", f"/sessions/{self.session_id}/suspend")
        self.session_data.update(result)
        return result

    def resume(self) -> dict[str, Any]:
        """Resume a suspended session."""
        result = self._cp_request("POST", f"/sessions/{self.session_id}/resume")
        self.session_data.update(result)
        self._sandbox = None  # connection descriptor may have changed
        return result

    def terminate(self) -> dict[str, Any]:
        """Terminate the session and release all resources."""
        result = self._cp_request("POST", f"/sessions/{self.session_id}/terminate")
        self.session_data.update(result)
        self._sandbox = None
        return result

    def refresh_connection(self) -> dict[str, Any]:
        """Refresh the connection credential (e.g. after resume)."""
        result = self._cp_request("POST", f"/sessions/{self.session_id}/connection")
        self.session_data.update(result)
        self._sandbox = None  # force re-creation with new credential
        return result

    # ------------------------------------------------------------------
    # Sandbox operations
    # ------------------------------------------------------------------

    def execute(
        self,
        command: str | list[str],
        *,
        cwd: str = "/tmp",  # nosec B108
        env: dict[str, str] | None = None,
        timeout_seconds: int = 60,
    ) -> CommandResult:
        """Execute a command inside the sandbox.

        Parameters
        ----------
        command:
            A shell command string (run via ``sh -c``) or a list of arguments.
        cwd:
            Working directory inside the Sandbox.
        env:
            Extra environment variables to set.
        timeout_seconds:
            Maximum execution time.

        Returns
        -------
        CommandResult
            The exit code, stdout, and stderr.
        """
        sandbox = self._get_sandbox()
        if isinstance(command, str):
            argv = ["sh", "-c", command]
        else:
            argv = command
        return sandbox.execute(argv, cwd=cwd, env=env, timeout_seconds=timeout_seconds)

    def write_file(self, path: str, content: str | bytes, *, mode: int = 0o644) -> None:
        """Write a file inside the sandbox.

        Parameters
        ----------
        path:
            Absolute path inside the Sandbox.
        content:
            File content as a string (UTF-8 encoded) or bytes.
        mode:
            POSIX permission bits (default: 0o644).
        """
        sandbox = self._get_sandbox()
        data = content.encode() if isinstance(content, str) else content
        sandbox.write_file(path, data, mode=mode)

    def read_file(self, path: str) -> str:
        """Read a file from the sandbox as a string.

        Parameters
        ----------
        path:
            Absolute path inside the Sandbox.

        Returns
        -------
        str
            The file content (decoded from bytes with replacement for invalid UTF-8).
        """
        sandbox = self._get_sandbox()
        return sandbox.read_file(path).decode(errors="replace")

    def read_file_bytes(self, path: str) -> bytes:
        """Read a file from the sandbox as raw bytes.

        Parameters
        ----------
        path:
            Absolute path inside the Sandbox.

        Returns
        -------
        bytes
            The raw file content.
        """
        sandbox = self._get_sandbox()
        return sandbox.read_file(path)

    def list_files(self, path: str = "/tmp") -> list[FileEntry]:  # nosec B108
        """List files and directories at the given path.

        Parameters
        ----------
        path:
            Directory path inside the Sandbox.

        Returns
        -------
        list[FileEntry]
            The directory entries.
        """
        sandbox = self._get_sandbox()
        return sandbox.list_files(path)

    def delete_file(self, path: str, *, recursive: bool = False) -> None:
        """Delete a file or directory from the sandbox.

        Parameters
        ----------
        path:
            Absolute path inside the Sandbox.
        recursive:
            If True, delete directories recursively.
        """
        sandbox = self._get_sandbox()
        sandbox.delete_file(path, recursive=recursive)

    # ------------------------------------------------------------------
    # Filesystem helpers
    # ------------------------------------------------------------------

    def file_exists(self, path: str) -> bool:
        """Check if a file or directory exists inside the sandbox.

        Parameters
        ----------
        path:
            Absolute path to check.

        Returns
        -------
        bool
        """
        sandbox = self._get_sandbox()
        return sandbox.file_exists(path)

    def file_info(self, path: str) -> FileInfo:
        """Get metadata about a file or directory.

        Parameters
        ----------
        path:
            Absolute path inside the Sandbox.

        Returns
        -------
        FileInfo
        """
        sandbox = self._get_sandbox()
        return sandbox.file_info(path)

    def make_dir(self, path: str, *, parents: bool = True) -> None:
        """Create a directory inside the sandbox.

        Parameters
        ----------
        path:
            Absolute path of the directory to create.
        parents:
            If ``True``, create parent directories as needed.
        """
        sandbox = self._get_sandbox()
        sandbox.make_dir(path, parents=parents)

    def rename_file(self, old_path: str, new_path: str) -> None:
        """Rename or move a file or directory inside the sandbox.

        Parameters
        ----------
        old_path:
            Current absolute path.
        new_path:
            Destination absolute path.
        """
        sandbox = self._get_sandbox()
        sandbox.rename_file(old_path, new_path)

    # ------------------------------------------------------------------
    # Recursive directory listing
    # ------------------------------------------------------------------

    def list_files_recursive(self, path: str = "/tmp", *, depth: int = 3) -> list[FileEntry]:  # nosec B108
        """List files recursively to a given depth.

        Parameters
        ----------
        path:
            Directory path inside the Sandbox.
        depth:
            Maximum depth (default: 3).

        Returns
        -------
        list[FileEntry]
        """
        sandbox = self._get_sandbox()
        return sandbox.list_files_recursive(path, depth=depth)

    # ------------------------------------------------------------------
    # Batch file write
    # ------------------------------------------------------------------

    def write_files(
        self,
        files: list[tuple[str, str | bytes]],
        *,
        mode: int = 0o644,
    ) -> None:
        """Write multiple files in sequence.

        Parameters
        ----------
        files:
            A list of ``(path, content)`` tuples.
        mode:
            POSIX permission bits (default: 0o644).
        """
        sandbox = self._get_sandbox()
        sandbox.write_files(files, mode=mode)

    # ------------------------------------------------------------------
    # Background process execution
    # ------------------------------------------------------------------

    def execute_background(
        self,
        command: str | list[str],
        *,
        cwd: str = "/tmp",  # nosec B108
        env: dict[str, str] | None = None,
    ) -> ProcessHandle:
        """Start a background process and return a handle.

        Parameters
        ----------
        command:
            A shell command string or list of arguments.
        cwd:
            Working directory inside the Sandbox.
        env:
            Extra environment variables.

        Returns
        -------
        ProcessHandle
        """
        sandbox = self._get_sandbox()
        return sandbox.execute_background(command, cwd=cwd, env=env)

    # ------------------------------------------------------------------
    # Streaming execution
    # ------------------------------------------------------------------

    def execute_stream(
        self,
        command: str | list[str],
        *,
        cwd: str = "/tmp",  # nosec B108
        env: dict[str, str] | None = None,
        timeout_seconds: int = 60,
        on_stdout: Any = None,
        on_stderr: Any = None,
    ) -> CommandResult:
        """Execute a command with streaming stdout/stderr callbacks.

        Parameters
        ----------
        command:
            A shell command string or list of arguments.
        cwd:
            Working directory inside the Sandbox.
        env:
            Extra environment variables.
        timeout_seconds:
            Maximum execution time.
        on_stdout:
            Called with each chunk of stdout bytes.
        on_stderr:
            Called with each chunk of stderr bytes.

        Returns
        -------
        CommandResult
        """
        sandbox = self._get_sandbox()
        if isinstance(command, str):
            argv = ["sh", "-c", command]
        else:
            argv = command
        return sandbox.execute_stream(
            argv,
            cwd=cwd,
            env=env,
            timeout_seconds=timeout_seconds,
            on_stdout=on_stdout,
            on_stderr=on_stderr,
        )

    # ------------------------------------------------------------------
    # Sandbox metrics
    # ------------------------------------------------------------------

    def get_metrics(self) -> Metrics:
        """Get the sandbox's current CPU, memory, and disk usage.

        Returns
        -------
        Metrics
        """
        sandbox = self._get_sandbox()
        return sandbox.get_metrics()

    # ------------------------------------------------------------------
    # PTY session
    # ------------------------------------------------------------------

    def open_pty(
        self,
        *,
        cols: int = 80,
        rows: int = 24,
        shell: str = "/bin/bash",
        cwd: str = "/tmp",  # nosec B108
    ) -> PtySession:
        """Open a pseudo-terminal session.

        Returns a simplified ``PtySession`` that wraps :meth:`execute` for
        request/response style interaction.

        Parameters
        ----------
        cols:
            Terminal width in columns (default: 80).
        rows:
            Terminal height in rows (default: 24).
        shell:
            Shell to start (default: ``/bin/bash``).
        cwd:
            Working directory (default: ``/tmp``).

        Returns
        -------
        PtySession
        """
        sandbox = self._get_sandbox()
        return sandbox.open_pty(cols=cols, rows=rows, shell=shell, cwd=cwd)  # nosec B604 - shell path, not subprocess

    # ------------------------------------------------------------------
    # File watching
    # ------------------------------------------------------------------

    def watch_files(
        self,
        path: str,
        *,
        recursive: bool = False,
        on_change: Any = None,
        poll_interval: float = 1.0,
        timeout: float = 60.0,
    ) -> list[FileEvent]:
        """Watch a directory for file changes using polling.

        Parameters
        ----------
        path:
            Directory path inside the Sandbox to watch.
        recursive:
            If ``True``, watch subdirectories recursively.
        on_change:
            Optional callback invoked for each detected change.
        poll_interval:
            Seconds between polls (default: 1.0).
        timeout:
            Maximum seconds to watch (default: 60.0).

        Returns
        -------
        list[FileEvent]
        """
        sandbox = self._get_sandbox()
        return sandbox.watch_files(
            path,
            recursive=recursive,
            on_change=on_change,
            poll_interval=poll_interval,
            timeout=timeout,
        )

    # ------------------------------------------------------------------
    # Git operations
    # ------------------------------------------------------------------

    @property
    def git(self) -> GitOperations:
        """Git operations wrapper for this sandbox.

        Returns
        -------
        GitOperations
        """
        sandbox = self._get_sandbox()
        return GitOperations(sandbox=sandbox)

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> SandboxSession:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        try:
            self.terminate()
        except Exception:  # nosec B110
            pass  # Best-effort cleanup; don't mask the original exception.

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_sandbox(self) -> SandboxConnection:
        """Return the sandbox connection, creating it lazily from the connection descriptor."""
        if self._sandbox is not None:
            return self._sandbox

        conn = self.connection
        if conn is None:
            raise RuntimeError(
                f"Session {self.session_id} has no connection descriptor. "
                f"Call wait_ready() first, or check is_ready."
            )

        self._sandbox = SandboxConnection.from_connection_descriptor(
            conn, http_client=self.http_client,
        )
        return self._sandbox

    def _cp_request(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Send an authenticated request to the Control Plane API."""
        url = urljoin(self.api_url.rstrip("/") + "/", path.lstrip("/"))
        data = json.dumps(body).encode() if body is not None else None
        headers: dict[str, str] = {"Content-Type": "application/json"} if data else {}

        headers = self.auth.apply(method, url, headers, data)

        client = self.http_client
        if client is not None:
            resp = client.request(method, url, content=data, headers=headers)
        else:
            resp = httpx.request(method, url, content=data, headers=headers)

        resp.raise_for_status()
        return resp.json()  # type: ignore[no-any-return]
