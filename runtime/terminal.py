# kiro-classification: public
"""The interactive pseudo-terminal (R7.5): `openpty`, bidirectional frames, window-size control.

The other half of the design's `Process manager` node. It is a separate module from
`runtime.process` for one substantive reason rather than for tidiness: `pty`, `termios` and
`fcntl` are POSIX-only, so importing this module on a platform without them fails. Keeping it
apart means a runtime that does not offer a terminal — and a test run on a platform that cannot
have one — still gets command execution and background processes, because nothing in
`runtime.process` imports this. The MicroVM image is Amazon Linux 2023 and CI runs on Ubuntu, so
the deployed and tested configurations both have all three; the split is what stops that being
an assumption baked into the whole runtime.

**Which terminal a frame belongs to.** `pty.data`, `pty.resize` and `pty.close` carry no session
identifier in their bodies — the catalogue gives `pty.data` a single `data` field — so the
terminal a frame addresses is the one whose `pty.open` carried the same correlation identifier in
the envelope. That is what the envelope's `id` is for, and using it means concurrent terminals
work with no change to the schema. A frame naming no open terminal is answered with
`error.decode` identifying `id`, which is the field that is actually wrong.

**Bytes in both directions, decoded in neither.** Terminal output is read with `os.read` and put
straight into `pty.data`; terminal input is taken from `pty.data` and written with `os.write`.
A terminal carries escape sequences, partial multi-byte characters and whatever a program chose
to emit, and a read boundary falls wherever the reader happened to stop, so decoding at either
end would corrupt exactly the traffic a terminal exists to carry. Writes loop over partial
writes rather than assuming one `os.write` takes everything, because a short write on a terminal
that is momentarily full would otherwise silently drop the tail of a keystroke burst.

**What this does not constrain.** The same posture as `runtime.process`: the terminal runs a
shell, arbitrary code runs in it, and that is the component's purpose. The containment is the
MicroVM boundary and the IAM policy on the Sandbox execution role, not anything here. The one
thing this module does insist on is that the shell is spawned as an argument vector, so no
request value is ever re-parsed as syntax — a terminal is the one place where a caller sending
shell syntax is expected, and it is expected *inside* the terminal, typed into a shell the
runtime started, not spliced into the runtime's own spawn.
"""

from __future__ import annotations

import asyncio
import fcntl
import os
import pty
import struct
import termios
from collections.abc import AsyncGenerator, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from typing import Final

from protocol.codec.values import Message
from protocol.schema import ENVELOPE_KEY_ID, Catalogue, load_catalogue
from runtime.bodies import (
    OperationRefusal,
    as_bytes,
    as_uint,
    named_body,
    refusal_reply,
    request_fields,
)
from runtime.operations import OperationRegistry, OperationReply
from runtime.process import DEFAULT_CHUNK_BYTES
from runtime.readiness import AdmissionClass

__all__ = [
    "DEFAULT_TERMINAL_COMMAND",
    "PTY_CLOSE",
    "PTY_DATA",
    "PTY_OPEN",
    "PTY_RESIZE",
    "TerminalManager",
    "register_terminal_operations",
]

#: The catalogue types this module serves.
PTY_OPEN: Final = "pty.open"
PTY_DATA: Final = "pty.data"
PTY_RESIZE: Final = "pty.resize"
PTY_CLOSE: Final = "pty.close"

#: What a terminal runs when nothing else is configured. `/bin/sh` rather than `$SHELL`, because
#: POSIX guarantees the former exists and the latter is an environment variable that may name a
#: program the image does not contain. A byte string, like every other argument vector here.
DEFAULT_TERMINAL_COMMAND: Final[tuple[bytes, ...]] = (b"/bin/sh",)

#: `TIOCSWINSZ` takes a `struct winsize`: four unsigned shorts, rows first.
_WINSIZE_FORMAT: Final = "HHHH"


@dataclass(slots=True)
class _Terminal:
    """One open pseudo-terminal: the master descriptor, the child, and the output queue."""

    master_fd: int
    process: asyncio.subprocess.Process
    #: `None` marks the end of output — end of file on the master, or a `pty.close` request.
    output: asyncio.Queue[bytes | None] = field(default_factory=asyncio.Queue)
    reading: bool = True


class TerminalManager:
    """Every pseudo-terminal open in one Sandbox_Runtime, keyed by correlation identifier."""

    def __init__(
        self,
        *,
        catalogue: Catalogue | None = None,
        command: Sequence[bytes] = DEFAULT_TERMINAL_COMMAND,
        chunk_bytes: int = DEFAULT_CHUNK_BYTES,
    ) -> None:
        self._catalogue = catalogue if catalogue is not None else load_catalogue()
        self._command = tuple(command)
        self._chunk_bytes = chunk_bytes
        self._terminals: dict[bytes, _Terminal] = {}

    @property
    def sessions(self) -> frozenset[bytes]:
        """The correlation identifier of every terminal currently open."""
        return frozenset(self._terminals)

    # --- R7.5: open a terminal and stream its output ------------------------------------

    async def open(self, request: Message) -> AsyncGenerator[OperationReply]:
        """Serve `pty.open`: `pty.data` for every read, then one `pty.close` at end of file.

        The stream ends when the master descriptor reaches end of file — which on Linux is an
        `EIO` from `os.read` once the child has closed the slave — or when a `pty.close` request
        arrives for this correlation identifier. Both are bounded: a terminal cannot stream
        forever with nothing on the other end, because the shell exits when its input is closed.
        """
        correlation = _correlation(request)
        if correlation in self._terminals:
            yield refusal_reply(
                self._catalogue,
                OperationRefusal(
                    "id",
                    "a pseudo-terminal is already open under this correlation identifier",
                ),
            )
            return

        fields = request_fields(self._catalogue, request)
        cols = as_uint(fields["cols"], "cols")
        rows = as_uint(fields["rows"], "rows")

        try:
            terminal = await self._spawn(cols=cols, rows=rows)
        except OSError as exc:
            yield refusal_reply(
                self._catalogue,
                OperationRefusal("id", f"opening a terminal failed: {exc}"),
            )
            return

        self._terminals[correlation] = terminal
        loop = asyncio.get_running_loop()
        loop.add_reader(terminal.master_fd, self._drain, terminal)
        try:
            while True:
                data = await terminal.output.get()
                if data is None:
                    break
                yield self._data(data)
            yield OperationReply(t=PTY_CLOSE, body={})
        finally:
            # Reached on end of file, on `pty.close`, and when the consumer abandons the stream.
            # All three have to release the descriptor and the child, or a hung-up WebSocket
            # would leave a shell running inside the Sandbox with nothing reading it.
            # Every step that must happen is synchronous and happens first. This block also runs
            # while this task is being cancelled — a WebSocket peer that hung up — and an await
            # in that state can raise immediately, so nothing that releases a resource sits
            # behind one. Reaping is the exception, and it is safe to skip: asyncio's child
            # watcher collects the child whether or not this `wait` completes.
            self._terminals.pop(correlation, None)
            self._stop_reading(loop, terminal)
            if terminal.process.returncode is None:
                with suppress(ProcessLookupError):
                    terminal.process.kill()
            os.close(terminal.master_fd)
            with suppress(asyncio.CancelledError):
                await terminal.process.wait()

    # --- R7.5: input and window-size control -------------------------------------------

    async def write(self, request: Message) -> AsyncGenerator[OperationReply]:
        """Serve an inbound `pty.data`: write the bytes to the terminal, answer nothing.

        Zero replies is the honest answer. A terminal echoes what it chooses to echo, on the
        output stream, so an acknowledgement here would be a second message saying something the
        protocol already says — and the catalogue has no type for it that is not `pty.data`
        itself, which would look like output the terminal never produced.
        """
        terminal = self._terminals.get(_correlation(request))
        if terminal is None:
            yield self._no_such_terminal()
            return
        fields = request_fields(self._catalogue, request)
        await _write_all(terminal.master_fd, as_bytes(fields["data"], "data"))

    async def resize(self, request: Message) -> AsyncGenerator[OperationReply]:
        """Serve `pty.resize`: set the window size, answer nothing.

        The window size is what makes a terminal interactive rather than a pipe — a full-screen
        program asks the kernel for it and redraws to fit — so R7.5's "window-size control" is
        this `ioctl` and not a value the runtime remembers on the side.
        """
        terminal = self._terminals.get(_correlation(request))
        if terminal is None:
            yield self._no_such_terminal()
            return
        fields = request_fields(self._catalogue, request)
        _set_window_size(
            terminal.master_fd,
            cols=as_uint(fields["cols"], "cols"),
            rows=as_uint(fields["rows"], "rows"),
        )

    async def close(self, request: Message) -> AsyncGenerator[OperationReply]:
        """Serve an inbound `pty.close`: end the output stream, answer nothing here.

        The `pty.close` the caller receives is emitted by the output stream as it finishes, not
        by this operation, so there is exactly one close frame per terminal whether the terminal
        was closed by the caller or by its own shell exiting.
        """
        terminal = self._terminals.get(_correlation(request))
        if terminal is None:
            yield self._no_such_terminal()
            return
        terminal.output.put_nowait(None)

    async def shutdown(self) -> None:
        """End every open terminal. See `ProcessManager.shutdown` for why this is not a hook."""
        for terminal in tuple(self._terminals.values()):
            terminal.output.put_nowait(None)
        # The `open` streams do the closing; this only asks them to. Yielding to the loop lets
        # them run, which is what makes a suite that shuts a manager down leave no shells behind.
        await asyncio.sleep(0)

    # --- Mechanics -----------------------------------------------------------------------

    async def _spawn(self, *, cols: int, rows: int) -> _Terminal:
        """Open a pseudo-terminal pair and start the shell as the session leader on it."""
        master_fd, slave_fd = pty.openpty()
        try:
            # The catalogue admits zero for both dimensions, and a terminal zero rows high is
            # not a thing a caller can mean. It is read as "unspecified", which leaves the pair
            # at the size `openpty` gave it rather than setting a size nothing can render.
            if cols and rows:
                _set_window_size(master_fd, cols=cols, rows=rows)
            os.set_blocking(master_fd, False)
            try:
                from runtime.confine import confine_child_process as _confine
            except ImportError:
                _confine = None

            def _pty_preexec():
                import os as _os
                _os.setsid()  # replaces start_new_session=True
                if _confine:
                    _confine()

            process = await asyncio.create_subprocess_exec(  # nosemgrep: dangerous-asyncio-create-exec-audit — sandbox runs arbitrary commands by design
                *self._command,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                preexec_fn=_pty_preexec,
            )
        except BaseException:
            os.close(master_fd)
            raise
        finally:
            # The parent's copy of the slave, closed in both outcomes. Holding it open would
            # keep the master from ever reaching end of file, because a descriptor to the slave
            # would still exist after the child exited.
            os.close(slave_fd)
        return _Terminal(master_fd=master_fd, process=process)

    def _drain(self, terminal: _Terminal) -> None:
        """Read whatever the terminal has produced. Called by the event loop, never awaited.

        A reader callback rather than a `StreamReader`: a pty master is not a pipe, and asyncio's
        pipe transports treat the `EIO` a master returns after its child exits as an error rather
        than as end of file, which is what it is here.
        """
        try:
            data = os.read(terminal.master_fd, self._chunk_bytes)
        except (BlockingIOError, InterruptedError):
            # Nothing to read after all, or a signal arrived mid-call. Neither ends the stream.
            return
        except OSError:
            # `EIO`: the last descriptor to the slave is gone. End of file for a terminal.
            data = b""
        if not data:
            terminal.output.put_nowait(None)
            return
        terminal.output.put_nowait(data)

    def _stop_reading(
        self, loop: asyncio.AbstractEventLoop, terminal: _Terminal
    ) -> None:
        """Detach the reader callback once, before the descriptor is closed."""
        if terminal.reading:
            terminal.reading = False
            loop.remove_reader(terminal.master_fd)

    def _data(self, data: bytes) -> OperationReply:
        return OperationReply(
            t=PTY_DATA, body=named_body(self._catalogue, PTY_DATA, {"data": data})
        )

    def _no_such_terminal(self) -> OperationReply:
        return refusal_reply(
            self._catalogue,
            OperationRefusal(
                "id",
                "no pseudo-terminal of this Sandbox is open under that "
                "correlation identifier",
            ),
        )


def _correlation(request: Message) -> bytes:
    """The envelope's correlation identifier, which is the terminal's identity here."""
    correlation = request[ENVELOPE_KEY_ID]
    if not isinstance(correlation, bytes):
        raise TypeError(
            f"decoded envelope key 'id' is {type(correlation).__name__}, not bytes"
        )
    return correlation


def _set_window_size(master_fd: int, *, cols: int, rows: int) -> None:
    """Set the terminal's window size. Rows first, as `struct winsize` declares them."""
    fcntl.ioctl(
        master_fd, termios.TIOCSWINSZ, struct.pack(_WINSIZE_FORMAT, rows, cols, 0, 0)
    )


async def _write_all(master_fd: int, data: bytes) -> None:
    """Write every byte to a non-blocking terminal, waiting for room rather than dropping.

    The master descriptor is non-blocking so that reading never stalls the event loop, which
    means a write can take less than it was given or nothing at all. Looping over the remainder
    and waiting on writability is what makes the input byte-exact: the terminal receives the
    bytes it was sent, in order, with no boundary of this loop's making visible to it.
    """
    loop = asyncio.get_running_loop()
    remaining = memoryview(data)
    while remaining:
        try:
            written = os.write(master_fd, remaining)
        except BlockingIOError:
            await _writable(loop, master_fd)
            continue
        remaining = remaining[written:]


async def _writable(loop: asyncio.AbstractEventLoop, master_fd: int) -> None:
    """Wait until the descriptor will accept a write."""
    ready = loop.create_future()
    loop.add_writer(master_fd, lambda: None if ready.done() else ready.set_result(None))
    try:
        await ready
    finally:
        loop.remove_writer(master_fd)


def register_terminal_operations(
    registry: OperationRegistry, *, manager: TerminalManager | None = None
) -> TerminalManager:
    """Route the four pseudo-terminal types onto a `TerminalManager`.

    All four are streaming registrations, including the three that answer with nothing: the
    streaming form is the one that admits a reply count of zero, and an input frame that produced
    an acknowledgement would be describing something the terminal did not do.

    `pty.open` is the runtime's one long-lived admission and the other three are ordinary in-flight
    requests. The asymmetry is the whole of the distinction: `pty.open` holds its admission until
    the peer closes the terminal, which is a decision no bound inside the Runtime can force, while
    a write, a resize and a close each end at the syscall they perform.
    """
    resolved = (
        manager
        if manager is not None
        else TerminalManager(catalogue=registry.catalogue)
    )
    registry.register_stream(
        PTY_OPEN, resolved.open, admission=AdmissionClass.LONG_LIVED
    )
    registry.register_stream(PTY_DATA, resolved.write)
    registry.register_stream(PTY_RESIZE, resolved.resize)
    registry.register_stream(PTY_CLOSE, resolved.close)
    return resolved
