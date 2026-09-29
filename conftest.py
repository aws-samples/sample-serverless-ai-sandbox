# kiro-classification: public
"""Suite-wide configuration: Hypothesis profiles and the outbound network denial.

This file sits at the repository root rather than under `tests/` so that it covers the tests
co-located with the module they cover as well as the ones under `tests/`; a `conftest.py`
one level down would leave the co-located half of the suite with working egress.

Hypothesis is pinned in `pyproject.toml` and is not reimplemented. The profiles below fix
the iteration floor the design's Testing Strategy sets; a property that needs more than the
floor states so on the test itself, as the codec properties do with `CODEC_EXAMPLES`.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from typing import Final

import pytest
from hypothesis import settings

from tests.harness import MINIMUM_EXAMPLES, NetworkGuard

_DEFAULT_PROFILE: Final = "default"

# Deadlines are disabled rather than tuned: a per-example wall-clock limit turns a slow
# shared runner into a false failure, and the suite's overall budget is enforced by
# pytest-timeout instead.
settings.register_profile(
    _DEFAULT_PROFILE,
    max_examples=MINIMUM_EXAMPLES,
    deadline=None,
    print_blob=True,
)

# CI starts from a clean checkout every run, so the example database has nothing to carry
# forward and is switched off rather than left to be silently empty.
settings.register_profile(
    "ci",
    parent=settings.get_profile(_DEFAULT_PROFILE),
    database=None,
)

settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", _DEFAULT_PROFILE))


@pytest.fixture(scope="session", autouse=True)
def deny_outbound_network() -> Iterator[NetworkGuard]:
    """Deny outbound network access for the whole session (R15.9)."""
    guard = NetworkGuard()
    guard.install()
    try:
        yield guard
    finally:
        guard.uninstall()


@pytest.fixture(scope="session", autouse=True)
def _disable_confinement_when_unprivileged() -> Iterator[None]:
    """Replace confine_child_process with a no-op when not running as root.

    The confinement preexec_fn (PCSR Finding 6) calls setuid, setgid, and capset,
    which require root. In production the runtime runs as root inside a Firecracker
    MicroVM; on CI runners and local dev the process is unprivileged. Patching the
    module attribute here lets the lazy imports in process.py and terminal.py pick
    up the no-op, so process-management tests exercise the real spawning logic
    without the confinement layer that only works inside a MicroVM.

    Production code is untouched — this patch lives entirely in test infrastructure.
    """
    if os.getuid() == 0:
        yield
        return

    import runtime.confine as _confine_mod

    # init() resolves ctypes handles; safe even without root.
    _confine_mod.init()

    original = _confine_mod.confine_child_process
    _confine_mod.confine_child_process = lambda: None  # type: ignore[assignment]
    try:
        yield
    finally:
        _confine_mod.confine_child_process = original
