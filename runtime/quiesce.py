# kiro-classification: public
"""The `/suspend` hook's body: flush pending filesystem writes, close outbound connections (R7.9).

R7.9 is one sentence with two verbs and an ordering. `runtime.hooks` owns the ordering — it closes
the readiness gate and waits for the admitted requests to drain *before* calling into this module,
which is R7.9's first clause and also the only thing that makes the second clause mean anything: a
flush performed while a request could still be writing has not flushed any particular state. What
is here is the two verbs.

## What "flush pending filesystem writes" has to be, given how the writes happen

`runtime.filesystem` writes a file by opening a descriptor, writing every byte and closing it. The
descriptor is gone by the time the operation replies, so at suspend time the runtime holds nothing
to flush: the bytes are in the kernel's page cache, attributed to a file nobody has open. That
rules out the obvious implementation — walk the open write handles and `fsync` each — because the
set is always empty, and an implementation over an always-empty set would be a no-op wearing the
shape of a flush.

The flush is therefore `sync(2)`, via `os.sync`. It is the operation that commits the page cache
for data whose descriptors are closed, which is exactly the data R7.9 is about. Inside a MicroVM
running one Session that is also not the blunt instrument it would be on a shared host: there is no
other tenant whose dirty pages are being flushed on this Session's behalf.

The configured root's directory descriptor is `fsync`ed first, and that part is *not* the data
flush — `fsync` on a directory commits the directory's own entries and nothing beneath it. It is
there for the error surface. `os.sync` returns nothing and reports nothing, so on its own it gives
a `/suspend` no way to fail; `fsync` on the root raises when the root has gone away underneath the
runtime, which is the one filesystem condition worth refusing a 200 for. A deployment with no
configured root has no such surface and the report says so rather than implying a check happened.

**Closing the filesystem write path** is the same argument from the other side. There is no path to
close, because each write closes its own descriptor and the gate now admits no request that could
open another. The design's phrasing describes the state after this returns; the gate is the
mechanism, and adding a second flag here that also refused writes would be a second authority on
readiness for the readiness gate to disagree with.

## "Close outbound connections" is a seam, and it is a list

The design says why this matters beyond tidiness: a connection held across a snapshot resumes
against a proxy that has since forgotten the flow, which hangs rather than failing cleanly. So the
close is real work with a real consequence — and it is work for whoever holds the connection, which
today is nothing in this package. The State_Store client is a one-method seam
(`runtime.run_config.StateStoreReader`, `runtime.persist.StateStoreWriter`), the egress identity
source is another (`runtime.egress_identity.EgressIdentitySource`), and each of those is where a
pooled HTTPS session would live in a deployment.

`OutboundConnections` is therefore one method, and `quiesce` takes a sequence of them rather than
one: the design's drawing has the hooks reaching both a State_Store client and an egress identity
manager, and a runtime that could close only one of them would be a runtime with a connection left
open. Every holder is attempted even after one of them fails, because the alternative is that one
misbehaving client leaves the rest of them open across the snapshot — which is the failure R7.9
exists to prevent, arrived at by way of reporting it.

## What suspend does *not* do

It does not stop, signal or reap the Sandbox's processes, and it does not close its pseudo-
terminals. That is the substantive difference between this hook and `/terminate`, and it follows
from R13.2 and R10.5 rather than from convenience: a suspended Session retains its filesystem *and
memory* state and restores both on resume, and a resume may be triggered by nothing more than a
request arriving at the endpoint. A `/suspend` that killed the agent's long-running build would
make auto-resume a promise about a Sandbox that had been quietly emptied. The processes are
suspended with the MicroVM, by the provider, which is what "retain memory state" means.

## Every wait is bounded, and one of them cannot be interrupted

The deadline bounds this hook. It does not bound `sync(2)`, which is not interruptible: the call
runs on a worker thread and a deadline that expires abandons the wait, not the syscall. That is
stated rather than hidden because it is the honest limit of what a bound can do here — the hook
returns a failure instead of hanging, which is what the requirement and the suite need, and the
kernel finishes the sync on its own schedule.
"""

from __future__ import annotations

import asyncio
import os
import time
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final, Protocol, runtime_checkable

from runtime.filesystem import ConfinedRoot

__all__ = [
    "DEFAULT_QUIESCE_DEADLINE_SECONDS",
    "OutboundConnections",
    "QuiesceFailure",
    "QuiesceReport",
    "quiesce",
]

#: How long the whole of `/suspend`'s quiesce may take when nothing else is configured. Generous,
#: because the thing being waited on is a filesystem commit whose duration is a property of how
#: much the Session wrote rather than of anything this runtime controls, and because the cost of
#: being wrong in the tight direction is a Sandbox that reports a failed suspend having flushed
#: successfully.
DEFAULT_QUIESCE_DEADLINE_SECONDS: Final = 30.0

#: The floor on what an outbound close is given, however much of the deadline the flush consumed.
#: A close granted zero seconds is not a close that failed, it is a close that never happened.
_MINIMUM_CLOSE_SECONDS: Final = 1.0

#: Opening the configured root to `fsync` it. `O_DIRECTORY` so a root that is no longer a directory
#: fails the open, `O_CLOEXEC` so the descriptor does not reach a process spawned meanwhile.
_ROOT_FLAGS: Final = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC


class QuiesceFailure(Exception):
    """The suspend hook could not flush, or could not close every outbound connection.

    Carries every failure rather than the first, because "which of them failed" is the whole of
    what an operator can act on and stopping at the first would hide the rest behind it.
    `runtime.hooks` does not catch this, so it becomes a non-200 from `/suspend` and the gate stays
    `SUSPENDED` — the Sandbox has stopped serving, which is correct, and has not claimed a
    durability it did not achieve, which is the point of raising at all.
    """


@runtime_checkable
class OutboundConnections(Protocol):
    """Something holding connections out of the MicroVM that a snapshot must not capture.

    One method, because that is the entire dependency: this module knows when to close and the
    holder knows what it has open. A State_Store client with a pooled HTTPS session satisfies it,
    and so does an egress identity source; neither has to inherit anything to do so.
    """

    async def close_outbound(self) -> None:
        """Close every connection out of the MicroVM, and do not reopen one until asked."""
        ...


@dataclass(frozen=True, slots=True)
class QuiesceReport:
    """What the quiesce did. Returned so that a caller can assert on it rather than infer it.

    `flushed_root` is False for a deployment with no configured filesystem root, which is a
    truthful "there was no root to commit the directory entries of" rather than a failure:
    `synced` is the flush that matters and it happens either way.
    """

    flushed_root: bool
    synced: bool
    closed: int


async def quiesce(
    *,
    root: ConfinedRoot | None = None,
    outbound: Sequence[OutboundConnections] = (),
    deadline_seconds: float = DEFAULT_QUIESCE_DEADLINE_SECONDS,
) -> QuiesceReport:
    """Flush pending filesystem writes and close every outbound connection (R7.9).

    Raises:
        QuiesceFailure: the flush or one of the closes did not complete.
    """
    if deadline_seconds <= 0:
        raise ValueError(
            f"a quiesce deadline is a positive number of seconds: {deadline_seconds}"
        )
    started = time.monotonic()
    failures: list[str] = []

    flushed_root = False
    synced = False
    try:
        async with asyncio.timeout(deadline_seconds):
            flushed_root = await asyncio.to_thread(_flush, root)
    except TimeoutError:
        failures.append(
            f"flushing pending filesystem writes did not complete within "
            f"{deadline_seconds:g}s"
        )
    except OSError as exc:
        failures.append(f"flushing pending filesystem writes failed: {exc}")
    else:
        synced = True

    closed = 0
    for connection in outbound:
        remaining = max(
            deadline_seconds - (time.monotonic() - started), _MINIMUM_CLOSE_SECONDS
        )
        described = type(connection).__name__
        try:
            async with asyncio.timeout(remaining):
                await connection.close_outbound()
        except TimeoutError:
            failures.append(
                f"closing the outbound connections of {described} did not complete "
                f"within {remaining:g}s"
            )
        except Exception as exc:  # noqa: BLE001 - every holder must still be attempted
            # A seam implementation may raise anything, and letting it propagate here would leave
            # the holders after it in the sequence open across the snapshot — which is the exact
            # condition R7.9 exists to prevent. So it is recorded and the loop continues, and the
            # accumulated failures become the raise below.
            failures.append(
                f"closing the outbound connections of {described} failed: "
                f"{type(exc).__name__}: {exc}"
            )
        else:
            closed += 1

    if failures:
        raise QuiesceFailure("; ".join(failures))
    return QuiesceReport(flushed_root=flushed_root, synced=synced, closed=closed)


def _flush(root: ConfinedRoot | None) -> bool:
    """Commit the page cache, and the root's directory entries where there is a root.

    Returns whether the root was `fsync`ed. Runs on a worker thread: both calls block, and the
    event loop they would otherwise block is the one that has to answer the `/terminate` that may
    follow this `/suspend`.
    """
    flushed_root = False
    if root is not None:
        descriptor = os.open(root.root, _ROOT_FLAGS)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        flushed_root = True
    # The data flush. See the module docstring: this and not the `fsync` above is what commits the
    # bytes written through `runtime.filesystem`, whose descriptors are long closed.
    os.sync()
    return flushed_root
