# kiro-classification: public
"""The iteration counts the design's Testing Strategy fixes are asserted, not documented."""

from __future__ import annotations

import pytest
from hypothesis import settings

from tests.harness import CODEC_EXAMPLES, MINIMUM_EXAMPLES


def test_the_loaded_profile_meets_the_iteration_floor() -> None:
    assert settings.default is not None
    assert settings.default.max_examples >= MINIMUM_EXAMPLES


def test_the_iteration_floor_and_the_codec_count_are_the_design_values() -> None:
    assert MINIMUM_EXAMPLES == 100
    assert CODEC_EXAMPLES == 1_000


@pytest.mark.parametrize("profile", ["default", "ci"])
def test_both_registered_profiles_meet_the_floor(profile: str) -> None:
    assert settings.get_profile(profile).max_examples >= MINIMUM_EXAMPLES


def test_a_per_example_deadline_is_not_enforced() -> None:
    """A wall-clock deadline per example turns a slow shared runner into a false failure."""
    assert settings.default is not None
    assert settings.default.deadline is None
