# kiro-classification: public
"""The readiness gate: the phase table, admission, and the drain that `/suspend` waits on.

Deterministic throughout. The property that quantifies over configurations and asserts that no
protocol request succeeds before `/run` returns 200 is Property 9, which is its own task; these
are the examples and edge cases underneath it, including the two orderings that a property over
whole configurations would not isolate: that `suspend` closes the gate before it waits, and that
a failed `/run` is distinguishable from one that has not happened yet.
"""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine

import pytest

from runtime.readiness import (
    IllegalPhaseTransition,
    NotServing,
    ReadinessGate,
    RuntimePhase,
)


def run[T](coroutine: Coroutine[object, object, T]) -> T:
    """Drive one coroutine to completion on its own loop.

    The gate's lock and event bind to the running loop on first use, so every scenario builds
    its own gate inside its own loop rather than sharing one across tests.
    """
    return asyncio.run(coroutine)


async def _refusal(gate: ReadinessGate) -> NotServing:
    """Attempt an admission that is expected to be refused, and return the refusal."""
    with pytest.raises(NotServing) as raised:
        async with gate.admit():
            pass
    return raised.value


def test_a_fresh_gate_is_closed_and_admits_nothing() -> None:
    async def scenario() -> None:
        gate = ReadinessGate()
        assert gate.phase is RuntimePhase.CLOSED
        assert gate.in_flight == 0

        refusal = await _refusal(gate)
        # Not terminal: nothing is wrong, `/run` has simply not happened yet.
        assert refusal.phase is RuntimePhase.CLOSED
        assert not refusal.is_terminal

    run(scenario())


def test_configuration_is_applied_behind_a_closed_handler() -> None:
    """R7.8's two halves as one sequence: closed during `/run`, open only after it."""

    async def scenario() -> None:
        gate = ReadinessGate()
        await gate.begin_start()
        assert gate.phase is RuntimePhase.STARTING
        assert not (await _refusal(gate)).is_terminal

        await gate.finish_start()
        assert gate.phase is RuntimePhase.SERVING
        async with gate.admit():
            assert gate.in_flight == 1
        assert gate.in_flight == 0

    run(scenario())


def test_a_second_run_hook_is_refused_rather_than_absorbed() -> None:
    """R7.12 requires the per-Session values generated once, so `/run` cannot repeat."""

    async def scenario() -> None:
        gate = ReadinessGate()
        await gate.begin_start()
        with pytest.raises(IllegalPhaseTransition) as during:
            await gate.begin_start()
        assert during.value.current is RuntimePhase.STARTING

        await gate.finish_start()
        with pytest.raises(IllegalPhaseTransition) as after:
            await gate.begin_start()
        assert after.value.current is RuntimePhase.SERVING
        # The refused transition changed nothing.
        assert gate.phase is RuntimePhase.SERVING

    run(scenario())


def test_a_failed_run_hook_is_terminal_and_keeps_its_reason() -> None:
    """R13.7: the reason that identifies the restoration failure outlives the response."""

    async def scenario() -> None:
        gate = ReadinessGate()
        await gate.begin_start()
        await gate.fail_start("restore of /work failed: artifact digest mismatch")

        assert gate.phase is RuntimePhase.FAILED
        refusal = await _refusal(gate)
        assert refusal.is_terminal
        assert "artifact digest mismatch" in str(refusal)

    run(scenario())


def test_suspend_and_resume_close_and_reopen_the_gate() -> None:
    async def scenario() -> None:
        gate = ReadinessGate()
        await gate.begin_start()
        await gate.finish_start()

        await gate.suspend()
        refusal = await _refusal(gate)
        assert refusal.phase is RuntimePhase.SUSPENDED
        # A suspended Sandbox resumes on request (R10.5), so this refusal is not terminal.
        assert not refusal.is_terminal

        await gate.resume()
        async with gate.admit():
            pass

    run(scenario())


def test_repeated_suspend_resume_and_terminate_are_absorbed() -> None:
    """Hooks are delivered by infrastructure and may arrive twice; only `/run` may not."""

    async def scenario() -> None:
        gate = ReadinessGate()
        await gate.begin_start()
        await gate.finish_start()

        await gate.suspend()
        await gate.suspend()
        assert gate.phase is RuntimePhase.SUSPENDED

        await gate.resume()
        await gate.resume()
        assert gate.phase is RuntimePhase.SERVING

        await gate.terminate()
        await gate.terminate()
        assert gate.phase is RuntimePhase.TERMINATED

    run(scenario())


def test_a_sandbox_that_never_ran_can_still_be_terminated() -> None:
    """The disposal path for an allocated-but-unused Sandbox (R11.10)."""

    async def scenario() -> None:
        gate = ReadinessGate()
        await gate.terminate()
        assert gate.phase is RuntimePhase.TERMINATED
        assert (await _refusal(gate)).is_terminal

    run(scenario())


def test_nothing_reopens_a_terminated_gate() -> None:
    async def scenario() -> None:
        gate = ReadinessGate()
        await gate.terminate()
        for reopen in (gate.begin_start(), gate.finish_start(), gate.resume()):
            with pytest.raises(IllegalPhaseTransition):
                await reopen
        assert gate.phase is RuntimePhase.TERMINATED

    run(scenario())


def test_suspend_closes_the_gate_before_it_waits_for_admitted_requests() -> None:
    """R7.9's ordering: new requests stop, then the admitted ones finish, then the flush.

    The assertion that matters is the last one. `suspend` returning only after the in-flight
    request has finished is what makes the caller's flush a flush of a quiet filesystem, rather
    than one racing a write it cannot see.
    """

    async def scenario() -> list[str]:
        gate = ReadinessGate()
        await gate.begin_start()
        await gate.finish_start()

        order: list[str] = []
        admitted = asyncio.Event()
        release = asyncio.Event()

        async def in_flight_request() -> None:
            async with gate.admit():
                admitted.set()
                await release.wait()
                order.append("request finished")

        async def suspender() -> None:
            await gate.suspend()
            order.append("suspend returned")

        request = asyncio.create_task(in_flight_request())
        await admitted.wait()
        assert gate.in_flight == 1

        suspend = asyncio.create_task(suspender())
        for _ in range(10):
            await asyncio.sleep(0)
            if gate.phase is RuntimePhase.SUSPENDED:
                break

        # Closed to new arrivals already, and still waiting on the admitted one.
        assert gate.phase is RuntimePhase.SUSPENDED
        assert not suspend.done()
        assert not (await _refusal(gate)).is_terminal

        release.set()
        await asyncio.gather(request, suspend)
        return order

    assert run(scenario()) == ["request finished", "suspend returned"]


def test_terminate_also_waits_for_admitted_requests() -> None:
    async def scenario() -> list[str]:
        gate = ReadinessGate()
        await gate.begin_start()
        await gate.finish_start()

        order: list[str] = []
        admitted = asyncio.Event()
        release = asyncio.Event()

        async def in_flight_request() -> None:
            async with gate.admit():
                admitted.set()
                await release.wait()
                order.append("request finished")

        request = asyncio.create_task(in_flight_request())
        await admitted.wait()

        terminate = asyncio.create_task(gate.terminate())
        for _ in range(10):
            await asyncio.sleep(0)
            if gate.phase is RuntimePhase.TERMINATED:
                break
        assert not terminate.done()

        release.set()
        await asyncio.gather(request, terminate)
        order.append("terminate returned")
        return order

    assert run(scenario()) == ["request finished", "terminate returned"]


def test_a_failing_request_still_leaves_the_gate_drained() -> None:
    """The in-flight count is released on the failure path too, or `/suspend` would hang."""

    async def scenario() -> None:
        gate = ReadinessGate()
        await gate.begin_start()
        await gate.finish_start()

        with pytest.raises(ZeroDivisionError):
            async with gate.admit():
                raise ZeroDivisionError
        assert gate.in_flight == 0

        # Which is to say: suspend completes rather than waiting on a request that died.
        await asyncio.wait_for(gate.suspend(), timeout=1)
        assert gate.phase is RuntimePhase.SUSPENDED

    run(scenario())
