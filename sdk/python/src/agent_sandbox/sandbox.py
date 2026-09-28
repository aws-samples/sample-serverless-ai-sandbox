# kiro-classification: public
"""Sandbox Protocol operations — execute commands and manage files inside a Sandbox.

Self-contained CBOR serialisation using ``cbor2``, independent of the main repo's
``protocol/`` package. The wire format matches the Sandbox_Protocol message catalogue
(``protocol/messages.yaml``).
"""

from __future__ import annotations

import os
import shlex
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Final

import cbor2
import httpx

__all__ = [
    "SandboxConnection",
    "CommandResult",
    "FileEntry",
    "FileInfo",
    "ProcessHandle",
    "Metrics",
    "PtySession",
    "FileEvent",
]

# ---------------------------------------------------------------------------
# Protocol constants — from the message catalogue
# ---------------------------------------------------------------------------

#: Envelope key positions (sorted ascending for deterministic CBOR).
_KEY_VERSION: Final = 1
_KEY_TYPE: Final = 2
_KEY_ID: Final = 3
_KEY_BODY: Final = 4

#: Protocol version emitted by this SDK.
_PROTOCOL_VERSION: Final = 1


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CommandResult:
    """Result of a command execution inside the Sandbox.

    Attributes
    ----------
    exit_code:
        Process exit code (0 = success, negative = killed by signal).
    stdout:
        Standard output as a string (decoded from bytes, replacing invalid UTF-8).
    stderr:
        Standard error as a string (decoded from bytes, replacing invalid UTF-8).
    """

    exit_code: int
    stdout: str
    stderr: str

    def __repr__(self) -> str:
        return (
            f"CommandResult(exit_code={self.exit_code}, "
            f"stdout={self.stdout!r}, stderr={self.stderr!r})"
        )


@dataclass(frozen=True, slots=True)
class FileEntry:
    """One entry from a directory listing.

    Attributes
    ----------
    name:
        File or directory name (not the full path).
    kind:
        One of ``"file"``, ``"directory"``, ``"symlink"``, ``"other"``.
    size:
        Size in bytes.
    """

    name: str
    kind: str
    size: int


@dataclass(frozen=True, slots=True)
class FileInfo:
    """Metadata about a single file or directory.

    Attributes
    ----------
    size:
        Size in bytes.
    modified:
        Last modification time as a Unix timestamp.
    permissions:
        Octal permission string (e.g. ``"644"``).
    file_type:
        Human-readable type (e.g. ``"regular file"``, ``"directory"``).
    path:
        Absolute path inside the Sandbox.
    """

    size: int
    modified: int
    permissions: str
    file_type: str
    path: str


@dataclass(frozen=True, slots=True)
class Metrics:
    """Sandbox resource usage snapshot.

    Attributes
    ----------
    memory_total_kb:
        Total memory in kilobytes.
    memory_available_kb:
        Available memory in kilobytes.
    disk_total:
        Total disk space (human-readable, e.g. ``"512M"``).
    disk_used:
        Used disk space (human-readable).
    disk_available:
        Available disk space (human-readable).
    load_avg_1:
        1-minute load average.
    load_avg_5:
        5-minute load average.
    load_avg_15:
        15-minute load average.
    """

    memory_total_kb: int
    memory_available_kb: int
    disk_total: str
    disk_used: str
    disk_available: str
    load_avg_1: float
    load_avg_5: float
    load_avg_15: float


# ---------------------------------------------------------------------------
# PTY session (simplified)
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class PtySession:
    """Pseudo-terminal session using execute() under the hood.

    Provides a request/response style interaction with a shell inside the
    Sandbox. For truly interactive sessions with real-time bidirectional I/O,
    use the WebSocket protocol path directly (``wss://<endpoint>/protocol``
    with ``pty.open`` / ``pty.data`` / ``pty.input`` messages).

    Parameters
    ----------
    sandbox:
        The ``SandboxConnection`` used to execute commands.
    shell:
        Shell to use (default: ``/bin/bash``).
    cwd:
        Working directory for commands (default: ``/tmp``).
    cols:
        Terminal width in columns (informational, default: 80).
    rows:
        Terminal height in rows (informational, default: 24).
    """

    sandbox: SandboxConnection
    shell: str = "/bin/bash"
    cwd: str = "/tmp"  # nosec B108
    cols: int = 80
    rows: int = 24
    _closed: bool = field(default=False, init=False, repr=False)

    def send(self, input_text: str, *, timeout_seconds: int = 10) -> str:
        """Send a command and return combined stdout + stderr.

        Parameters
        ----------
        input_text:
            The command to execute.
        timeout_seconds:
            Maximum execution time (default: 10).

        Returns
        -------
        str
            Combined stdout and stderr output.

        Raises
        ------
        RuntimeError
            If the PTY session has been closed.
        """
        if self._closed:
            raise RuntimeError("PTY session is closed")
        result = self.sandbox.execute(
            [self.shell, "-c", input_text],
            cwd=self.cwd,
            timeout_seconds=timeout_seconds,
        )
        output = result.stdout
        if result.stderr:
            output += result.stderr
        return output

    def send_and_receive(
        self,
        input_text: str,
        *,
        timeout_seconds: int = 10,
    ) -> CommandResult:
        """Send a command and return the full CommandResult.

        Like :meth:`send`, but returns the structured result with separate
        stdout, stderr, and exit code.

        Parameters
        ----------
        input_text:
            The command to execute.
        timeout_seconds:
            Maximum execution time.

        Returns
        -------
        CommandResult
        """
        if self._closed:
            raise RuntimeError("PTY session is closed")
        return self.sandbox.execute(
            [self.shell, "-c", input_text],
            cwd=self.cwd,
            timeout_seconds=timeout_seconds,
        )

    def resize(self, cols: int, rows: int) -> None:
        """Update the terminal dimensions (informational in simplified mode).

        Parameters
        ----------
        cols:
            New terminal width.
        rows:
            New terminal height.
        """
        self.cols = cols
        self.rows = rows

    def close(self) -> None:
        """Close the PTY session."""
        self._closed = True

    def __enter__(self) -> PtySession:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()


# ---------------------------------------------------------------------------
# File event for file watching
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FileEvent:
    """A detected file change inside the Sandbox.

    Attributes
    ----------
    path:
        Absolute path of the changed file.
    event_type:
        One of ``"created"``, ``"modified"``, ``"deleted"``.
    size:
        File size in bytes (0 for deleted files).
    """

    path: str
    event_type: str
    size: int = 0


# ---------------------------------------------------------------------------
# Process handle for background execution
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class ProcessHandle:
    """Handle to a background process running inside the Sandbox.

    Created by :meth:`SandboxConnection.execute_background`. Provides methods
    to check status, read output, wait for completion, and kill the process.

    Parameters
    ----------
    pid:
        The process ID inside the Sandbox.
    sandbox:
        The ``SandboxConnection`` used to interact with the process.
    stdout_path:
        Path to the file capturing stdout inside the Sandbox.
    stderr_path:
        Path to the file capturing stderr inside the Sandbox.
    """

    pid: int
    sandbox: SandboxConnection
    stdout_path: str
    stderr_path: str

    def is_running(self) -> bool:
        """Return ``True`` if the process is still running."""
        result = self.sandbox.execute(
            ["kill", "-0", str(self.pid)], timeout_seconds=5,
        )
        return result.exit_code == 0

    def read_stdout(self) -> str:
        """Read the current stdout output."""
        try:
            return self.sandbox.read_file(self.stdout_path).decode(errors="replace")
        except Exception:
            return ""

    def read_stderr(self) -> str:
        """Read the current stderr output."""
        try:
            return self.sandbox.read_file(self.stderr_path).decode(errors="replace")
        except Exception:
            return ""

    def kill(self) -> None:
        """Send SIGKILL to the process."""
        self.sandbox.execute(["kill", "-9", str(self.pid)], timeout_seconds=5)

    def send_stdin(self, data: str) -> None:
        """Send data to the process's standard input.

        Uses a named pipe (FIFO) to deliver input to the running process.
        This is a best-effort mechanism — full interactive stdin streaming
        requires WebSocket transport.

        Parameters
        ----------
        data:
            The text to send to stdin.

        Raises
        ------
        RuntimeError
            If the process is no longer running.
        """
        if not self.is_running():
            raise RuntimeError(f"Process {self.pid} is no longer running")

        # Write data to process stdin via /proc/<pid>/fd/0 if accessible,
        # otherwise use a helper file approach
        stdin_file = f"/tmp/.stdin_{self.pid}"  # nosec B108
        self.sandbox.write_file(stdin_file, data.encode(), mode=0o644)
        # Pipe the file contents to the process's stdin
        self.sandbox.execute(
            ["sh", "-c", f"cat {stdin_file} > /proc/{self.pid}/fd/0 2>/dev/null || true"],
            timeout_seconds=5,
        )
        # Clean up
        self.sandbox.execute(["rm", "-f", stdin_file], timeout_seconds=5)

    def wait(self, *, timeout: int = 60) -> CommandResult:
        """Wait for the process to finish and return the result.

        Parameters
        ----------
        timeout:
            Maximum seconds to wait.

        Returns
        -------
        CommandResult
            The final stdout, stderr, and exit code.
        """
        # Use a shell wait loop: poll until process ends or timeout
        result = self.sandbox.execute(
            [
                "sh", "-c",
                f"i=0; while kill -0 {self.pid} 2>/dev/null && [ $i -lt {timeout} ]; do "  # nosemgrep: string-concat-in-list — intentional
                f"sleep 1; i=$((i+1)); done; "
                f"wait {self.pid} 2>/dev/null; echo $?",
            ],
            timeout_seconds=timeout + 5,
        )
        exit_code_str = result.stdout.strip().split("\n")[-1]
        try:
            exit_code = int(exit_code_str)
        except ValueError:
            exit_code = -1

        return CommandResult(
            exit_code=exit_code,
            stdout=self.read_stdout(),
            stderr=self.read_stderr(),
        )


# ---------------------------------------------------------------------------
# Sandbox Protocol client
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SandboxConnection:
    """Speaks the Sandbox Protocol (CBOR over HTTPS) to a MicroVM endpoint.

    Parameters
    ----------
    base_url:
        The dedicated HTTPS endpoint for the Sandbox.
    auth_header_name:
        The header name the endpoint requires (e.g. ``X-aws-proxy-auth``).
    auth_header_value:
        The JWE token value.
    http_client:
        An ``httpx.Client`` instance for connection pooling. If ``None``, a new
        client is created per request.
    """

    base_url: str
    auth_header_name: str
    auth_header_value: str
    http_client: httpx.Client | None = None

    @classmethod
    def from_connection_descriptor(
        cls,
        descriptor: dict[str, Any],
        *,
        http_client: httpx.Client | None = None,
    ) -> SandboxConnection:
        """Build from the ``connection`` map returned by the Control Plane."""
        return cls(
            base_url=descriptor["baseUrl"],
            auth_header_name=descriptor["authHeaderName"],
            auth_header_value=descriptor["authHeaderValue"],
            http_client=http_client,
        )

    # ------------------------------------------------------------------
    # High-level operations
    # ------------------------------------------------------------------

    def execute(
        self,
        command: list[str],
        *,
        cwd: str = "/tmp",  # nosec B108
        env: dict[str, str] | None = None,
        timeout_seconds: int = 60,
    ) -> CommandResult:
        """Execute a command inside the Sandbox and return the result.

        Parameters
        ----------
        command:
            The command as a list of arguments (e.g. ``["python3", "-c", "print(1)"]``).
        cwd:
            Working directory inside the Sandbox.
        env:
            Extra environment variables to set.
        timeout_seconds:
            Maximum execution time in seconds.

        Returns
        -------
        CommandResult
            The exit code, stdout, and stderr.
        """
        body: dict[int, Any] = {
            1: [arg.encode() for arg in command],       # argv: list[bytes]
            2: cwd.encode(),                             # cwd: bytes
            3: {k.encode(): v.encode() for k, v in (env or {}).items()},  # env: map
            4: timeout_seconds * 1000,                   # timeoutMs: uint (ms)
            5: False,                                    # stream: bool
        }

        response = self._send("exec.request", body, timeout_seconds=timeout_seconds + 10)
        resp_body = response[_KEY_BODY]

        exit_code = resp_body.get(1, -1)
        stdout_bytes = resp_body.get(2, b"")
        stderr_bytes = resp_body.get(3, b"")

        return CommandResult(
            exit_code=exit_code if isinstance(exit_code, int) else -1,
            stdout=stdout_bytes.decode(errors="replace") if isinstance(stdout_bytes, bytes) else str(stdout_bytes),
            stderr=stderr_bytes.decode(errors="replace") if isinstance(stderr_bytes, bytes) else str(stderr_bytes),
        )

    def write_file(self, path: str, content: bytes, *, mode: int = 0o644) -> None:
        """Write a file inside the Sandbox.

        Parameters
        ----------
        path:
            Absolute path inside the Sandbox.
        content:
            File content as bytes.
        mode:
            POSIX permission bits (default: 0o644).
        """
        body: dict[int, Any] = {
            1: path.encode(),  # path: bytes
            2: content,        # data: bytes
            3: mode,           # mode: uint
        }
        self._send("fs.write", body)

    def read_file(self, path: str) -> bytes:
        """Read a file from the Sandbox.

        Parameters
        ----------
        path:
            Absolute path inside the Sandbox.

        Returns
        -------
        bytes
            The file content.
        """
        body: dict[int, Any] = {1: path.encode()}  # path: bytes
        response = self._send("fs.read", body)
        resp_body = response[_KEY_BODY]
        content = resp_body.get(1, b"")
        if not isinstance(content, bytes):
            raise RuntimeError(f"Expected bytes from fs.content, got {type(content).__name__}")
        return content

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
        body: dict[int, Any] = {1: path.encode()}  # path: bytes
        response = self._send("fs.list", body)
        resp_body = response[_KEY_BODY]

        entries_raw = resp_body.get(1, [])
        entries: list[FileEntry] = []
        if isinstance(entries_raw, list):
            for entry in entries_raw:
                if isinstance(entry, dict):
                    name_bytes = entry.get(1, b"")
                    name = name_bytes.decode(errors="replace") if isinstance(name_bytes, bytes) else str(name_bytes)
                    kind = entry.get(2, "other")
                    size = entry.get(3, 0)
                    entries.append(FileEntry(name=name, kind=kind, size=size))

        return entries

    def delete_file(self, path: str, *, recursive: bool = False) -> None:
        """Delete a file or directory from the Sandbox.

        Parameters
        ----------
        path:
            Absolute path inside the Sandbox.
        recursive:
            If True, delete directories recursively.
        """
        body: dict[int, Any] = {
            1: path.encode(),  # path: bytes
            2: recursive,      # recursive: bool
        }
        self._send("fs.delete", body)

    # ------------------------------------------------------------------
    # Filesystem helpers
    # ------------------------------------------------------------------

    def file_exists(self, path: str) -> bool:
        """Check if a file or directory exists inside the Sandbox.

        Parameters
        ----------
        path:
            Absolute path to check.

        Returns
        -------
        bool
            ``True`` if the path exists, ``False`` otherwise.
        """
        result = self.execute(["test", "-e", path], timeout_seconds=5)
        return result.exit_code == 0

    def file_info(self, path: str) -> FileInfo:
        """Get metadata about a file or directory.

        Parameters
        ----------
        path:
            Absolute path inside the Sandbox.

        Returns
        -------
        FileInfo
            Size, modification time, permissions, type, and path.

        Raises
        ------
        RuntimeError
            If stat fails (e.g. file does not exist).
        """
        result = self.execute(
            ["stat", "-c", "%s %Y %a %F %n", path], timeout_seconds=5,
        )
        if result.exit_code != 0:
            raise RuntimeError(f"stat failed for {path}: {result.stderr}")
        parts = result.stdout.strip().split(None, 4)
        if len(parts) < 5:
            raise RuntimeError(f"Unexpected stat output: {result.stdout!r}")
        return FileInfo(
            size=int(parts[0]),
            modified=int(parts[1]),
            permissions=parts[2],
            file_type=parts[3],
            path=parts[4],
        )

    def make_dir(self, path: str, *, parents: bool = True) -> None:
        """Create a directory inside the Sandbox.

        Parameters
        ----------
        path:
            Absolute path of the directory to create.
        parents:
            If ``True`` (default), create parent directories as needed.

        Raises
        ------
        RuntimeError
            If mkdir fails.
        """
        cmd = ["mkdir", "-p", path] if parents else ["mkdir", path]
        result = self.execute(cmd, timeout_seconds=5)
        if result.exit_code != 0:
            raise RuntimeError(f"mkdir failed: {result.stderr}")

    def rename_file(self, old_path: str, new_path: str) -> None:
        """Rename or move a file or directory inside the Sandbox.

        Parameters
        ----------
        old_path:
            Current absolute path.
        new_path:
            Destination absolute path.

        Raises
        ------
        RuntimeError
            If the rename fails.
        """
        result = self.execute(["mv", old_path, new_path], timeout_seconds=5)
        if result.exit_code != 0:
            raise RuntimeError(f"rename failed: {result.stderr}")

    # ------------------------------------------------------------------
    # Recursive directory listing
    # ------------------------------------------------------------------

    def list_files_recursive(self, path: str = "/tmp", *, depth: int = 3) -> list[FileEntry]:  # nosec B108
        """List files recursively to a given depth.

        Uses ``find`` to traverse the directory tree up to *depth* levels.

        Parameters
        ----------
        path:
            Directory path inside the Sandbox.
        depth:
            Maximum depth to recurse (default: 3).

        Returns
        -------
        list[FileEntry]
            All entries found, with ``kind`` derived from the ``find`` type indicator.
        """
        result = self.execute(
            ["find", path, "-maxdepth", str(depth), "-printf", "%y %s %p\\n"],
            timeout_seconds=10,
        )
        if result.exit_code != 0:
            raise RuntimeError(f"find failed: {result.stderr}")

        type_map = {"f": "file", "d": "directory", "l": "symlink"}
        entries: list[FileEntry] = []
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            parts = line.split(None, 2)
            if len(parts) < 3:
                continue
            kind = type_map.get(parts[0], "other")
            try:
                size = int(parts[1])
            except ValueError:
                size = 0
            entries.append(FileEntry(name=parts[2], kind=kind, size=size))
        return entries

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
            A list of ``(path, content)`` tuples. Content may be ``str`` or ``bytes``.
        mode:
            POSIX permission bits for all files (default: 0o644).
        """
        for path, content in files:
            data = content.encode() if isinstance(content, str) else content
            self.write_file(path, data, mode=mode)

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

        The command's stdout and stderr are redirected to temporary files inside
        the Sandbox so they can be read incrementally.

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
            A handle with the PID and methods to read output, check status,
            wait, or kill.
        """
        if isinstance(command, list):
            cmd_str = " ".join(shlex.quote(arg) for arg in command)
        else:
            cmd_str = command  # String commands are passed as-is for shell features (pipes, redirects)

        # Use a unique tag for the temp files, get PID after starting
        tag = os.urandom(4).hex()
        stdout_path = f"/tmp/.bg_stdout_{tag}"  # nosec B108
        stderr_path = f"/tmp/.bg_stderr_{tag}"  # nosec B108

        result = self.execute(
            [
                "sh", "-c",
                f"nohup sh -c '{cmd_str}' > {stdout_path} 2> {stderr_path} & echo $!",
            ],
            cwd=cwd,
            env=env,
            timeout_seconds=10,
        )
        pid_str = result.stdout.strip()
        try:
            pid = int(pid_str)
        except ValueError:
            raise RuntimeError(f"Failed to start background process, got: {result.stdout!r}")

        return ProcessHandle(
            pid=pid,
            sandbox=self,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
        )

    # ------------------------------------------------------------------
    # Streaming execution via WebSocket
    # ------------------------------------------------------------------

    def execute_stream(
        self,
        command: list[str],
        *,
        cwd: str = "/tmp",  # nosec B108
        env: dict[str, str] | None = None,
        timeout_seconds: int = 60,
        on_stdout: Callable[[bytes], None] | None = None,
        on_stderr: Callable[[bytes], None] | None = None,
    ) -> CommandResult:
        """Execute a command with streaming stdout/stderr callbacks.

        Uses WebSocket transport (``wss://<endpoint>/protocol``) when possible.
        Falls back to file-tailing over HTTP if WebSocket connection fails.

        Parameters
        ----------
        command:
            The command as a list of arguments.
        cwd:
            Working directory inside the Sandbox.
        env:
            Extra environment variables.
        timeout_seconds:
            Maximum execution time.
        on_stdout:
            Called with each chunk of stdout bytes as it arrives.
        on_stderr:
            Called with each chunk of stderr bytes as it arrives.

        Returns
        -------
        CommandResult
            The final exit code, stdout, and stderr.
        """
        try:
            return self._stream_via_websocket(
                command,
                cwd=cwd,
                env=env,
                timeout_seconds=timeout_seconds,
                on_stdout=on_stdout,
                on_stderr=on_stderr,
            )
        except Exception:
            # Fallback: file-tailing approach
            return self._stream_via_files(
                command,
                cwd=cwd,
                env=env,
                timeout_seconds=timeout_seconds,
                on_stdout=on_stdout,
                on_stderr=on_stderr,
            )

    def _stream_via_websocket(
        self,
        command: list[str],
        *,
        cwd: str,
        env: dict[str, str] | None,
        timeout_seconds: int,
        on_stdout: Callable[[bytes], None] | None,
        on_stderr: Callable[[bytes], None] | None,
    ) -> CommandResult:
        """Stream using the WebSocket protocol path."""
        import websockets.sync.client as ws_client  # type: ignore[import-untyped]

        ws_url = self.base_url.rstrip("/").replace("https://", "wss://").replace("http://", "wss://") + "/protocol"

        body: dict[int, Any] = {
            1: [arg.encode() for arg in command],
            2: cwd.encode(),
            3: {k.encode(): v.encode() for k, v in (env or {}).items()},
            4: timeout_seconds * 1000,
            5: True,  # stream: true
        }

        request_id = os.urandom(16)
        envelope: dict[int, Any] = {
            _KEY_VERSION: _PROTOCOL_VERSION,
            _KEY_TYPE: "exec.request",
            _KEY_ID: request_id,
            _KEY_BODY: body,
        }
        wire = cbor2.dumps(envelope, canonical=True)

        stdout_parts: list[bytes] = []
        stderr_parts: list[bytes] = []
        exit_code = -1

        headers = {self.auth_header_name: self.auth_header_value}

        with ws_client.connect(
            ws_url,
            additional_headers=headers,
            close_timeout=5,
            open_timeout=10,
        ) as ws:
            ws.send(wire)

            while True:
                raw = ws.recv()
                if isinstance(raw, str):
                    raw = raw.encode()
                msg = cbor2.loads(raw)
                msg_type = msg.get(_KEY_TYPE, "")
                msg_body = msg.get(_KEY_BODY, {})

                if msg_type == "exec.chunk":
                    stream_id = msg_body.get(1, 0)  # 0=stdout, 1=stderr
                    data = msg_body.get(2, b"")
                    if not isinstance(data, bytes):
                        data = str(data).encode()
                    if stream_id == 0:
                        stdout_parts.append(data)
                        if on_stdout:
                            on_stdout(data)
                    else:
                        stderr_parts.append(data)
                        if on_stderr:
                            on_stderr(data)

                elif msg_type == "exec.result":
                    exit_code = msg_body.get(1, -1)
                    if not isinstance(exit_code, int):
                        exit_code = -1
                    # Collect any final stdout/stderr from the result
                    final_stdout = msg_body.get(2, b"")
                    final_stderr = msg_body.get(3, b"")
                    if isinstance(final_stdout, bytes) and final_stdout:
                        stdout_parts.append(final_stdout)
                        if on_stdout:
                            on_stdout(final_stdout)
                    if isinstance(final_stderr, bytes) and final_stderr:
                        stderr_parts.append(final_stderr)
                        if on_stderr:
                            on_stderr(final_stderr)
                    break

                elif msg_type == "error":
                    error_msg = msg_body.get(1, b"unknown error")
                    if isinstance(error_msg, bytes):
                        error_msg = error_msg.decode(errors="replace")
                    raise RuntimeError(f"Sandbox error: {error_msg}")

        return CommandResult(
            exit_code=exit_code,
            stdout=b"".join(stdout_parts).decode(errors="replace"),
            stderr=b"".join(stderr_parts).decode(errors="replace"),
        )

    def _stream_via_files(
        self,
        command: list[str],
        *,
        cwd: str,
        env: dict[str, str] | None,
        timeout_seconds: int,
        on_stdout: Callable[[bytes], None] | None,
        on_stderr: Callable[[bytes], None] | None,
    ) -> CommandResult:
        """Fallback streaming: redirect to files and tail them."""
        import time

        tag = os.urandom(4).hex()
        stdout_path = f"/tmp/.stream_stdout_{tag}"  # nosec B108
        stderr_path = f"/tmp/.stream_stderr_{tag}"  # nosec B108

        cmd_str = " ".join(shlex.quote(arg) for arg in command)
        # Start the command in background with output redirected
        start_result = self.execute(
            [
                "sh", "-c",
                f"nohup sh -c '{cmd_str}' > {stdout_path} 2> {stderr_path} & echo $!",
            ],
            cwd=cwd,
            env=env,
            timeout_seconds=10,
        )
        pid_str = start_result.stdout.strip()
        try:
            pid = int(pid_str)
        except ValueError:
            raise RuntimeError(f"Failed to start streaming process: {start_result.stdout!r}")

        stdout_offset = 0
        stderr_offset = 0
        deadline = time.monotonic() + timeout_seconds

        while time.monotonic() < deadline:
            # Check if process is still running
            alive = self.execute(["kill", "-0", str(pid)], timeout_seconds=5)

            # Read new stdout (read_file returns bytes on SandboxConnection)
            try:
                raw_stdout = self.read_file(stdout_path)
                new_stdout = raw_stdout[stdout_offset:]
                if new_stdout and on_stdout:
                    on_stdout(new_stdout)
                stdout_offset = len(raw_stdout)
            except Exception:  # nosec B110
                pass

            # Read new stderr
            try:
                raw_stderr = self.read_file(stderr_path)
                new_stderr = raw_stderr[stderr_offset:]
                if new_stderr and on_stderr:
                    on_stderr(new_stderr)
                stderr_offset = len(raw_stderr)
            except Exception:  # nosec B110
                pass

            if alive.exit_code != 0:
                break
            time.sleep(0.5)  # nosemgrep: arbitrary-sleep — polling loop by design

        # Final read — just use whatever we've already accumulated
        try:
            full_stdout = self.read_file(stdout_path)
        except Exception:
            full_stdout = b""
        try:
            full_stderr = self.read_file(stderr_path)
        except Exception:
            full_stderr = b""

        # Get exit code
        wait_result = self.execute(
            ["sh", "-c", f"wait {pid} 2>/dev/null; echo $?"],
            timeout_seconds=5,
        )
        try:
            exit_code = int(wait_result.stdout.strip().split("\n")[-1])
        except ValueError:
            exit_code = -1

        # Cleanup temp files
        try:
            self.delete_file(stdout_path)
            self.delete_file(stderr_path)
        except Exception:  # nosec B110
            pass

        stdout_str = full_stdout.decode(errors="replace") if isinstance(full_stdout, bytes) else str(full_stdout)
        stderr_str = full_stderr.decode(errors="replace") if isinstance(full_stderr, bytes) else str(full_stderr)
        return CommandResult(exit_code=exit_code, stdout=stdout_str, stderr=stderr_str)

    # ------------------------------------------------------------------
    # Sandbox metrics
    # ------------------------------------------------------------------

    def get_metrics(self) -> Metrics:
        """Get the Sandbox's current CPU, memory, and disk usage.

        Returns
        -------
        Metrics
            A snapshot of resource utilisation.
        """
        result = self.execute(
            [
                "sh", "-c",
                "cat /proc/meminfo | head -3; echo '---'; "  # nosemgrep: string-concat-in-list — intentional
                "df /tmp | tail -1; echo '---'; "
                "cat /proc/loadavg",
            ],
            timeout_seconds=5,
        )
        if result.exit_code != 0:
            raise RuntimeError(f"metrics collection failed: {result.stderr}")

        sections = result.stdout.split("---")

        # Parse /proc/meminfo
        mem_total = 0
        mem_available = 0
        if len(sections) >= 1:
            for line in sections[0].strip().split("\n"):
                if line.startswith("MemTotal:"):
                    mem_total = int(line.split()[1])
                elif line.startswith("MemAvailable:") or line.startswith("MemFree:"):
                    mem_available = int(line.split()[1])

        # Parse df output
        disk_total = ""
        disk_used = ""
        disk_available = ""
        if len(sections) >= 2:
            df_parts = sections[1].strip().split()
            if len(df_parts) >= 4:
                disk_total = df_parts[1]
                disk_used = df_parts[2]
                disk_available = df_parts[3]

        # Parse /proc/loadavg
        load_1 = 0.0
        load_5 = 0.0
        load_15 = 0.0
        if len(sections) >= 3:
            load_parts = sections[2].strip().split()
            if len(load_parts) >= 3:
                load_1 = float(load_parts[0])
                load_5 = float(load_parts[1])
                load_15 = float(load_parts[2])

        return Metrics(
            memory_total_kb=mem_total,
            memory_available_kb=mem_available,
            disk_total=disk_total,
            disk_used=disk_used,
            disk_available=disk_available,
            load_avg_1=load_1,
            load_avg_5=load_5,
            load_avg_15=load_15,
        )

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

        Returns a simplified ``PtySession`` that uses :meth:`execute` under the
        hood for request/response style interaction. For truly interactive
        sessions with real-time bidirectional I/O, use the WebSocket protocol
        path directly (``wss://<endpoint>/protocol`` with ``pty.open`` /
        ``pty.data`` / ``pty.input`` messages).

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
            A handle to the interactive terminal session.
        """
        return PtySession(
            sandbox=self,
            shell=shell,  # nosec B604
            cwd=cwd,
            cols=cols,
            rows=rows,
        )

    # ------------------------------------------------------------------
    # File watching (polling-based)
    # ------------------------------------------------------------------

    def watch_files(
        self,
        path: str,
        *,
        recursive: bool = False,
        on_change: Callable[[FileEvent], None] | None = None,
        poll_interval: float = 1.0,
        timeout: float = 60.0,
    ) -> list[FileEvent]:
        """Watch a directory for file changes using polling.

        Compares directory listings between poll intervals to detect created,
        modified, and deleted files. For real-time file watching, use
        ``inotifywait`` inside the sandbox via :meth:`execute`.

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
            All file events detected during the watch period.
        """
        import time

        events: list[FileEvent] = []
        depth_args = [] if recursive else ["-maxdepth", "1"]

        def _snapshot() -> dict[str, int]:
            """Take a snapshot of files with their sizes."""
            result = self.execute(
                ["find", path, *depth_args, "-type", "f", "-printf", "%s %p\\n"],
                timeout_seconds=10,
            )
            files: dict[str, int] = {}
            for line in result.stdout.strip().split("\n"):
                if not line:
                    continue
                parts = line.split(None, 1)
                if len(parts) == 2:
                    try:
                        files[parts[1]] = int(parts[0])  # size as proxy for change
                    except ValueError:
                        pass
            return files

        # Take initial snapshot
        known_files = _snapshot()

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            time.sleep(poll_interval)  # nosemgrep: arbitrary-sleep — polling loop by design

            current = _snapshot()

            # Detect new and modified files
            for fpath, mtime in current.items():
                if fpath not in known_files:
                    evt = FileEvent(path=fpath, event_type="created", size=mtime)
                    events.append(evt)
                    if on_change is not None:
                        on_change(evt)
                elif mtime != known_files[fpath]:
                    evt = FileEvent(path=fpath, event_type="modified", size=mtime)
                    events.append(evt)
                    if on_change is not None:
                        on_change(evt)

            # Detect deleted files
            for fpath in known_files:
                if fpath not in current:
                    evt = FileEvent(path=fpath, event_type="deleted", size=0)
                    events.append(evt)
                    if on_change is not None:
                        on_change(evt)

            known_files = current

            if events:
                break  # Return on first batch of changes

        return events

    # ------------------------------------------------------------------
    # Protocol transport
    # ------------------------------------------------------------------

    def _send(self, message_type: str, body: dict[int, Any], *, timeout_seconds: int = 300) -> dict[int, Any]:
        """Serialise a protocol message, send it, and return the decoded response."""
        request_id = os.urandom(16)

        # Build the deterministic envelope — keys must be ascending integers.
        envelope: dict[int, Any] = {
            _KEY_VERSION: _PROTOCOL_VERSION,
            _KEY_TYPE: message_type,
            _KEY_ID: request_id,
            _KEY_BODY: body,
        }
        wire = cbor2.dumps(envelope, canonical=True)

        url = self.base_url.rstrip("/") + "/protocol"
        headers = {
            self.auth_header_name: self.auth_header_value,
            "Content-Type": "application/cbor",
        }

        client = self.http_client
        if client is not None:
            resp = client.post(url, content=wire, headers=headers, timeout=timeout_seconds)
        else:
            resp = httpx.post(url, content=wire, headers=headers, timeout=timeout_seconds)

        resp.raise_for_status()
        return cbor2.loads(resp.content)  # type: ignore[no-any-return]
