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
