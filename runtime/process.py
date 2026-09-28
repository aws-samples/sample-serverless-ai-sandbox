# kiro-classification: public
"""The process manager: arbitrary commands, streamed output, and background processes.

This is the `Process manager` node of the design's Sandbox_Runtime drawing, less the
pseudo-terminal, which is `runtime.terminal`. It covers R7.1, R7.2 and R7.3, and it exists to
run code the Sandbox's caller wrote, which is the component's entire purpose.

**What this module constrains, and what it does not.** It does not constrain what a command may
do. There is no allowlist, no argument inspection and no path restriction on the executable,
because the design settles the question and settles it the other way: "the Sandbox_Runtime is
*not* a security control. Every guarantee this design makes about what a Sandbox cannot do is
enforced outside the MicroVM." The containment is the MicroVM boundary, the Sandbox execution
role's IAM policy, the absence of any route out except the connector, and the Egress_Controller.
A check here would be a check performed by the neighbour of the code it is meant to constrain.
So the two things this module does insist on are the two that are *not* about the command:

- **No shell, ever.** Every invocation is an argument vector handed to `execvp` semantics, so
  nothing in a request is re-parsed as syntax. `exec.request` and `proc.start` both type `argv`
  as a list of byte strings in the catalogue rather than a command line, which is what makes
  this possible without the runtime having to quote anything. A caller who wants a shell asks
  for one explicitly as `argv[0]`, and then it is the caller's own shell with the caller's own
  quoting, which is a different thing from this module building a command string.
- **Handles are unguessable.** A background handle is 16 bytes from `secrets`, not a counter, so
  presenting a handle is evidence of having been given it. Not because that is the security
  boundary — it is not — but because a predictable handle would make a process registry
  enumerable for no benefit.

**Bytes, everywhere, decoded nowhere.** No call in this module passes `text=`, `encoding=` or
`universal_newlines=` to a subprocess, and none is available to be passed by accident: the
whole module reads `bytes` off a pipe with `StreamReader.read` and puts `bytes` in a message
body. Chunk boundaries fall at arbitrary byte positions — `read(n)` returns whatever has
arrived — so a multi-byte sequence can and will straddle two chunks. That is the point rather
than a hazard: because nothing decodes, re-joining the chunks is concatenation, and the
concatenation is byte-identical to the captured output. This is the mechanism the design names
for R8.9 ("read from file descriptors as bytes and never decoded inside the Runtime"), and it
is why `exec.chunk.data`, `exec.result.stdout` and `exec.result.stderr` are byte strings in the
catalogue.

Argument vectors, working directories and environments are byte strings for the same reason a
filename is: a path on a Linux filesystem is a byte sequence and need not be valid UTF-8. They
are passed to the subprocess machinery as `bytes` rather than being decoded and re-encoded,
which would fail on exactly the arguments that make byte-typing necessary.

**Deviation from the design's mechanism column, with reasoning.** The design names `posix_spawn`
with pipes for R7.1 and `waitid` with `WNOWAIT` for R7.3. This module uses
`asyncio.create_subprocess_exec` and reads `Process.returncode`. The observable behaviour is the
one the design specifies — `subprocess` reaches `posix_spawn` itself where the platform allows
it, and asyncio's child watcher reaps the child and records its status without any call here
blocking — and going lower would mean this module owning pipe creation, non-blocking reads and
reaping, none of which R7.1 to R7.3 say anything about. `WNOWAIT` exists so that a status query
does not consume the exit status and make a second query lie; asyncio achieves the same end by
reaping once, centrally, and remembering the result, which is why a status query here is a
memory read rather than a syscall.
"""

from __future__ import annotations

import asyncio
import errno
import os
import secrets
from collections.abc import AsyncGenerator, Iterable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from typing import Final

from protocol.codec.values import Message, Value
from protocol.schema import Catalogue, load_catalogue
from runtime.bodies import (
    OperationRefusal,
    as_bool,
    as_bytes,
    as_uint,
    named_body,
    refusal_reply,
    request_fields,
)
from runtime.operations import OperationRegistry, OperationReply

__all__ = [
    "DEFAULT_CHUNK_BYTES",
    "EXEC_CHUNK",
    "EXEC_REQUEST",
    "EXEC_RESULT",
    "EXIT_CODE_NOT_EXECUTABLE",
    "EXIT_CODE_NOT_FOUND",
    "PROC_HANDLE",
    "PROC_START",
    "PROC_STATUS",
    "STREAM_STDERR",
    "STREAM_STDOUT",
    "Invocation",
    "ProcessManager",
    "argv_of",
    "exit_code_of",
    "read_invocation",
    "register_process_operations",
    "spawn",
]

#: The catalogue types this module serves and answers with.
EXEC_REQUEST: Final = "exec.request"
EXEC_CHUNK: Final = "exec.chunk"
EXEC_RESULT: Final = "exec.result"
PROC_START: Final = "proc.start"
PROC_HANDLE: Final = "proc.handle"
PROC_STATUS: Final = "proc.status"

#: `exec.chunk.stream`, as the catalogue comments it: 0 stdout, 1 stderr.
STREAM_STDOUT: Final = 0
STREAM_STDERR: Final = 1

#: How much is read from a pipe at a time. A boundary, not a record separator: the reader takes
#: whatever has arrived up to this much, so a chunk ends wherever the writer happened to stop.
DEFAULT_CHUNK_BYTES: Final = 65536

#: The shell's own conventions for a command that could not be run, reused rather than invented.
#: The catalogue affords no "spawn failed" message — there are exactly two error types and
#: neither describes it — and inventing one would be a protocol change made to improve an error
#: message. A caller that asked to run a command that does not exist gets the answer a shell
#: gives: an ordinary result, exit code 127, and the operating system's reason on stderr.
EXIT_CODE_NOT_FOUND: Final = 127
EXIT_CODE_NOT_EXECUTABLE: Final = 126

#: `exec.result.exitCode` and `proc.status.exitCode` are declared -255..255. A status outside
#: that would fail encoding, so it is clamped here, where the reason can be stated, rather than
#: raising out of an operation. Nothing on Linux produces one: an exit status is 0..255 and a
#: termination signal is reported as -N for N no greater than 64.
_EXIT_CODE_FLOOR: Final = -255
_EXIT_CODE_CEILING: Final = 255

#: `proc.status.state`, as the catalogue's enum declares it.
_STATE_RUNNING: Final = "running"
_STATE_EXITED: Final = "exited"
_STATE_SIGNALLED: Final = "signalled"

#: Errno values that mean "found it, could not execute it" rather than "did not find it".
_NOT_EXECUTABLE: Final = frozenset(
    {errno.EACCES, errno.EPERM, errno.ENOEXEC, errno.EISDIR}
)


@dataclass(frozen=True, slots=True)
class Invocation:
    """What to run, where, and with what environment. Byte strings throughout.

    `cwd` of None and `env` of None both mean "inherit the runtime's own", which is how an empty
    `cwd` byte string and an empty `env` map in a request are read. The catalogue makes both
    fields present rather than optional, so emptiness is the only way a caller can say
    "unspecified", and reading an empty environment map as "run with no environment at all"
    would make the common request — run this, inherit everything — inexpressible.
    """

    argv: tuple[bytes, ...]
    cwd: bytes | None = None
    env: Mapping[bytes, bytes] | None = None


def read_invocation(fields: Mapping[str, Value]) -> Invocation:
    """Read the `argv`, `cwd` and `env` fields that `exec.request` and `proc.start` share.

    Raises `OperationRefusal` for an empty argument vector, which is the one thing a
    schema-conforming request can still fail to name: `argv[0]` is the executable, so a list of
    length zero asks for nothing to be run.
    """
    raw_argv = fields["argv"]
    if not isinstance(raw_argv, list):
        raise TypeError(f"field 'argv' is {type(raw_argv).__name__}, not a list")
    argv = tuple(as_bytes(element, "argv") for element in raw_argv)
    if not argv:
        raise OperationRefusal("argv", "an argument vector must name an executable")

    cwd = as_bytes(fields["cwd"], "cwd") or None

    raw_env = fields["env"]
    if not isinstance(raw_env, dict):
        raise TypeError(f"field 'env' is {type(raw_env).__name__}, not a map")
    env = {
        as_bytes(key, "env key"): as_bytes(value, "env value")
        for key, value in raw_env.items()
    } or None

    return Invocation(argv=argv, cwd=cwd, env=env)


def exit_code_of(returncode: int) -> int:
    """A process status as `exec.result.exitCode` declares it, clamped to the declared range."""
    return max(_EXIT_CODE_FLOOR, min(_EXIT_CODE_CEILING, returncode))


def spawn_failure_code(exc: OSError) -> int:
    """The shell's exit code for a command that could not be run. See `EXIT_CODE_NOT_FOUND`."""
    return (
        EXIT_CODE_NOT_EXECUTABLE
        if exc.errno in _NOT_EXECUTABLE
        else EXIT_CODE_NOT_FOUND
    )


def spawn_failure_detail(exc: OSError) -> bytes:
    """Why a spawn failed, as bytes for a byte-typed field, and never decoded on the way out."""
    return os.fsencode(str(exc))


async def spawn(
    invocation: Invocation,
    *,
    stdout: int,
    stderr: int,
) -> asyncio.subprocess.Process:
    """Start `invocation` with no shell.

    The argument vector is passed positionally to `create_subprocess_exec`, which is the
    `execvp` form: no string is built and nothing is re-parsed. Deliberately not
    `create_subprocess_shell`, and there is no code path here that reaches it.
    """
    try:
        from runtime.confine import confine_child_process as _confine
    except ImportError:
        _confine = None
    return await asyncio.create_subprocess_exec(  # nosemgrep: dangerous-asyncio-create-exec-audit — sandbox runs arbitrary commands by design
        *invocation.argv,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=stdout,
        stderr=stderr,
        cwd=invocation.cwd,
        env=invocation.env,
        preexec_fn=_confine,
    )


#: How many random bytes a background handle is built from. 16 bytes rendered as hex, so the
#: handle is a 32-byte ASCII byte string: byte-typed because the catalogue types it `carries:
#: name`, and hex rather than raw so it survives being written into a log line unchanged.
_HANDLE_BYTES: Final = 16


@dataclass(slots=True)
class _Background:
    """One background process, and the task that reaps it.

    The reaping task exists so that `returncode` is populated the moment the child exits rather
    than the next time something asks. That is what makes a status query a memory read, and it is
    this module's answer to the design's `WNOWAIT`: the status is consumed once, here, and every
    query afterwards reads the remembered value instead of racing to consume it.
    """

    handle: bytes
    process: asyncio.subprocess.Process
    waiter: asyncio.Task[int]


class ProcessManager:
    """Runs commands and holds the background process registry for one Sandbox_Runtime.

    One per runtime process, because the registry is the thing that gives R7.3's handles meaning
    and a second registry would be a second set of handles for one Sandbox.
    """

    def __init__(
        self,
        *,
        catalogue: Catalogue | None = None,
        chunk_bytes: int = DEFAULT_CHUNK_BYTES,
    ) -> None:
        self._catalogue = catalogue if catalogue is not None else load_catalogue()
        self._chunk_bytes = chunk_bytes
        self._background: dict[bytes, _Background] = {}

    @property
    def handles(self) -> frozenset[bytes]:
        """Every background handle this registry currently answers to."""
        return frozenset(self._background)

    # --- R7.1 and R7.2: run a command, stream its output, report its exit -----------------

    async def execute(self, request: Message) -> AsyncGenerator[OperationReply]:
        """Serve `exec.request`: chunks as they are produced, then one `exec.result`.

        The reply count follows the request's `stream` field, which is why this is registered as
        a streaming operation even though it often answers once. With `stream` false the caller
        gets exactly one `exec.result`, which the request/response transport carries; with
        `stream` true it gets every chunk first, which needs the WebSocket.

        R7.2 is satisfied by *when* a chunk is yielded, not by the fact that chunks exist. Each
        one is yielded as soon as a read returns, before the process has exited and before
        anything else has been read, so a caller sees output while the command is still running.
        Every chunk yielded is also appended to the accumulator the final result is built from,
        so the concatenation of the chunks equals the captured output exactly. It is the same
        `bytes` object in both places rather than two derivations of one read, which is why no
        chunk boundary can be visible in the result and no re-joining rule is needed.
        """
        fields = request_fields(self._catalogue, request)
        try:
            invocation = read_invocation(fields)
        except OperationRefusal as refusal:
            yield refusal_reply(self._catalogue, refusal)
            return

        timeout_ms = as_uint(fields["timeoutMs"], "timeoutMs")
        streaming = as_bool(fields["stream"], "stream")

        try:
            process = await spawn(
                invocation,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError as exc:
            yield self._result(spawn_failure_code(exc), b"", spawn_failure_detail(exc))
            return

        captured: dict[int, bytearray] = {
            STREAM_STDOUT: bytearray(),
            STREAM_STDERR: bytearray(),
        }
        chunks: asyncio.Queue[tuple[int, bytes] | None] = asyncio.Queue()
        readers = self._start_readers(process, chunks)
        loop = asyncio.get_running_loop()
        deadline = None if timeout_ms == 0 else loop.time() + timeout_ms / 1000

        try:
            while True:
                remaining = None if deadline is None else deadline - loop.time()
                try:
                    item = await asyncio.wait_for(chunks.get(), timeout=remaining)
                except TimeoutError:
                    # The command outlived its deadline. Kill it, then keep draining with no
                    # deadline: the output it already produced is real output, and the pipes
                    # reach end of file promptly once the process is gone.
                    _kill(process)
                    deadline = None
                    continue
                if item is None:
                    break
                stream_id, chunk = item
                captured[stream_id] += chunk
                if streaming:
                    yield self._chunk(stream_id, chunk)

            returncode = await process.wait()
            yield self._result(
                exit_code_of(returncode),
                bytes(captured[STREAM_STDOUT]),
                bytes(captured[STREAM_STDERR]),
            )
        finally:
            # Reached on the ordinary path and also when the consumer abandons this generator
            # mid-stream — a WebSocket peer that hung up, say. Either way the child must not
            # outlive the request that started it, and the reader tasks must not outlive the
            # queue nobody is draining.
            for reader in readers:
                reader.cancel()
            if process.returncode is None:
                # Killed synchronously, before anything is awaited. This block also runs while
                # *this* task is being cancelled, and an await in that state can raise
                # immediately, so the signal must not be behind one. Reaping can be: asyncio's
                # child watcher collects the child whether or not this `wait` completes.
                _kill(process)
                with suppress(asyncio.CancelledError):
                    await process.wait()

    def _start_readers(
        self,
        process: asyncio.subprocess.Process,
        chunks: asyncio.Queue[tuple[int, bytes] | None],
    ) -> tuple[asyncio.Task[None], ...]:
        """Start one reader per pipe, plus the task that marks the end of both.

        Two readers rather than one alternating between the pipes, because a command that writes
        a great deal to stderr and nothing to stdout must not be able to stall: each pipe is
        drained independently and the consumer sees whichever chunk arrived first.
        """

        async def pump(stream_id: int, reader: asyncio.StreamReader) -> None:
            while True:
                # `read`, not `readline`: a chunk boundary is wherever the write happened to
                # stop, which is the whole reason the data is carried as bytes.
                chunk = await reader.read(self._chunk_bytes)
                if not chunk:
                    return
                await chunks.put((stream_id, chunk))

        if process.stdout is None or process.stderr is None:
            raise TypeError("a piped subprocess must expose both stdout and stderr")
        pumps = (
            asyncio.create_task(pump(STREAM_STDOUT, process.stdout)),
            asyncio.create_task(pump(STREAM_STDERR, process.stderr)),
        )

        async def mark_end() -> None:
            await asyncio.gather(*pumps)
            await chunks.put(None)

        return (*pumps, asyncio.create_task(mark_end()))

    # --- R7.3: background processes, a handle, and a status ------------------------------

    async def start(self, request: Message) -> OperationReply:
        """Serve `proc.start`: spawn, register under a fresh handle, and report it.

        Standard output and standard error go to `/dev/null` rather than being buffered. That is
        a deliberate limitation and worth naming: `exec.chunk` carries no handle field, so the
        protocol as catalogued has no way to deliver a *background* process's output to a
        caller, and buffering it against a delivery mechanism that does not exist would grow
        without bound inside a MicroVM. The design's drawing points the process manager at a
        CloudWatch Logs emitter, which is where that output belongs; wiring it there is that
        component's task, and this is the seam it will replace.
        """
        try:
            invocation = read_invocation(request_fields(self._catalogue, request))
        except OperationRefusal as refusal:
            return refusal_reply(self._catalogue, refusal)

        try:
            process = await spawn(
                invocation,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
        except OSError as exc:
            # Unlike `exec.request` there is no result message to carry an exit code, so the
            # failure has to be reported as the offending field. `argv[0]` is what did not run.
            return refusal_reply(
                self._catalogue,
                OperationRefusal("argv", os.fsdecode(spawn_failure_detail(exc))),
            )

        handle = secrets.token_hex(_HANDLE_BYTES).encode("ascii")
        self._background[handle] = _Background(
            handle=handle,
            process=process,
            waiter=asyncio.create_task(process.wait()),
        )
        return OperationReply(
            t=PROC_HANDLE,
            body=named_body(
                self._catalogue,
                PROC_HANDLE,
                {"handle": handle, "pid": process.pid},
            ),
        )

    async def status(self, request: Message) -> OperationReply:
        """Serve `proc.status`: the state of the process a handle names.

        `exitCode` is omitted while the process is running rather than set to a placeholder,
        which is the catalogue's own reasoning for making that field optional: a running process
        has no exit code, and reporting one would make it indistinguishable from a process that
        exited with that value.

        Only `handle` is read. `proc.status` is declared `both`, so one schema describes the
        question and the answer, and its `state` field is not optional — which means a caller
        cannot ask without also asserting a state it does not know. Whatever it asserts is
        ignored here. That is a wart in the catalogue rather than in this module and it is
        reported as such: closing it would mean a separate query type, which is a change to
        `protocol/messages.yaml`, the document both codecs and the committed vector corpus are
        built from, and not a change to make from inside an operation.
        """
        fields = request_fields(self._catalogue, request)
        handle = as_bytes(fields["handle"], "handle")
        entry = self._background.get(handle)
        if entry is None:
            return refusal_reply(
                self._catalogue,
                OperationRefusal(
                    "handle",
                    "no background process of this Sandbox answers to that handle",
                ),
            )

        reported: dict[str, Value] = {"handle": handle}
        returncode = entry.process.returncode
        if returncode is None:
            reported["state"] = _STATE_RUNNING
        else:
            reported["state"] = _STATE_SIGNALLED if returncode < 0 else _STATE_EXITED
            reported["exitCode"] = exit_code_of(returncode)
        return OperationReply(
            t=PROC_STATUS, body=named_body(self._catalogue, PROC_STATUS, reported)
        )

    async def shutdown(self) -> None:
        """Kill every registered background process and reap it.

        Not a lifecycle hook and not wired to one here: `/suspend` and `/terminate` sequence
        their own work through `LifecycleActions`, and this is the operation that whichever task
        implements those actions will call. It exists now because a process registry that could
        not be emptied would leak children out of every test that used it.
        """
        for entry in tuple(self._background.values()):
            if entry.process.returncode is None:
                _kill(entry.process)
            await entry.waiter
        self._background.clear()

    # --- Message bodies -----------------------------------------------------------------

    def _chunk(self, stream_id: int, data: bytes) -> OperationReply:
        return OperationReply(
            t=EXEC_CHUNK,
            body=named_body(
                self._catalogue, EXEC_CHUNK, {"stream": stream_id, "data": data}
            ),
        )

    def _result(self, exit_code: int, stdout: bytes, stderr: bytes) -> OperationReply:
        return OperationReply(
            t=EXEC_RESULT,
            body=named_body(
                self._catalogue,
                EXEC_RESULT,
                {"exitCode": exit_code, "stdout": stdout, "stderr": stderr},
            ),
        )


def _kill(process: asyncio.subprocess.Process) -> None:
    """Kill a process, tolerating one that has already exited.

    `SIGKILL` rather than `SIGTERM`, because this is only reached when a deadline expired or the
    caller went away, and in both cases the runtime has stopped waiting for the process to
    cooperate. A graceful stop is the caller's to ask for, and it has a handle to ask with.
    """
    try:
        process.kill()
    except ProcessLookupError:
        # It exited between the status check and the signal. Nothing to do and nothing wrong.
        pass


def register_process_operations(
    registry: OperationRegistry, *, manager: ProcessManager | None = None
) -> ProcessManager:
    """Route the three command and process types onto a `ProcessManager`.

    Returns the manager so the caller keeps a reference to shut down; a registry holding the
    only reference would leave background processes with no way to be reaped.
    """
    resolved = (
        manager if manager is not None else ProcessManager(catalogue=registry.catalogue)
    )
    registry.register_stream(EXEC_REQUEST, resolved.execute)
    registry.register(PROC_START, resolved.start)
    registry.register(PROC_STATUS, resolved.status)
    return resolved


def argv_of(command: Iterable[str | bytes]) -> tuple[bytes, ...]:
    """An argument vector as byte strings, for a caller holding text.

    `os.fsencode` and not `str.encode`, so that a name the filesystem produced round-trips
    through this exactly as the filesystem gave it.
    """
    return tuple(
        element if isinstance(element, bytes) else os.fsencode(element)
        for element in command
    )
