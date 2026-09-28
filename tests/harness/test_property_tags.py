# kiro-classification: public
"""The per-property tagging comment form is enforced, so a tag cannot quietly go missing."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from tests.harness import (
    FEATURE_NAME,
    PROPERTY_COUNT,
    REPOSITORY_ROOT,
    collect_python_property_tests,
    parse_property_tag,
)

WELL_FORMED_TAG = [
    f"# Feature: {FEATURE_NAME}, Property 3: For any byte sequence, including sequences",
    "# that are not valid UTF-8, carrying that sequence as process output through one",
    "# serialise and deserialise cycle yields a byte sequence identical to the input.",
]


def test_the_design_example_parses() -> None:
    tag = parse_property_tag(WELL_FORMED_TAG)
    assert tag is not None
    assert tag.feature == FEATURE_NAME
    assert tag.number == 3
    assert tag.summary.startswith("For any byte sequence")
    assert tag.summary.endswith("identical to the input.")
    assert tag.is_well_formed


def test_a_single_line_tag_parses() -> None:
    tag = parse_property_tag(
        [f"# Feature: {FEATURE_NAME}, Property 44: A one-line summary."]
    )
    assert tag is not None
    assert tag.number == 44
    assert tag.summary == "A one-line summary."


@pytest.mark.parametrize(
    "line",
    [
        "# Property 3: the feature name is missing",
        f"# Feature: {FEATURE_NAME} Property 3: the comma is missing",
        f"# Feature: {FEATURE_NAME}, Property: the number is missing",
        f"# Feature: {FEATURE_NAME}, Property 3 the colon is missing",
        f"# feature: {FEATURE_NAME}, Property 3: the label is lowercased",
        f"# Feature: {FEATURE_NAME}, Property 3:",
        "# an ordinary comment",
    ],
)
def test_malformed_tags_are_rejected(line: str) -> None:
    assert parse_property_tag([line]) is None


def test_a_foreign_feature_or_out_of_range_number_is_not_well_formed() -> None:
    foreign = parse_property_tag(
        ["# Feature: some-other-feature, Property 3: summary."]
    )
    assert foreign is not None and not foreign.is_well_formed

    out_of_range = parse_property_tag(
        [f"# Feature: {FEATURE_NAME}, Property {PROPERTY_COUNT + 1}: summary."]
    )
    assert out_of_range is not None and not out_of_range.is_well_formed


def test_collection_finds_the_tag_above_the_decorators(tmp_path: Path) -> None:
    module = tmp_path / "test_sample_property.py"
    module.write_text(
        textwrap.dedent(
            f"""
            from hypothesis import given, settings
            from hypothesis import strategies as st

            # Feature: {FEATURE_NAME}, Property 3: For any byte sequence, carrying it as
            # process output through one round trip yields the input bytes.
            @given(data=st.binary())
            @settings(max_examples=1000)
            def test_process_output_is_byte_exact(data: bytes) -> None:
                assert data == data

            def test_not_a_property() -> None:
                assert True
            """
        ).lstrip(),
        encoding="utf-8",
    )

    collected = collect_python_property_tests(tmp_path)

    assert len(collected) == 1
    found = collected[0]
    assert found.name == "test_process_output_is_byte_exact"
    assert found.tag is not None
    assert found.tag.number == 3
    assert found.tag.is_well_formed


def test_collection_reports_an_untagged_property_test(tmp_path: Path) -> None:
    module = tmp_path / "test_untagged.py"
    module.write_text(
        textwrap.dedent(
            """
            from hypothesis import given
            from hypothesis import strategies as st

            @given(value=st.integers())
            def test_untagged(value: int) -> None:
                assert value == value
            """
        ).lstrip(),
        encoding="utf-8",
    )

    collected = collect_python_property_tests(tmp_path)

    assert len(collected) == 1
    assert collected[0].tag is None


def test_every_property_test_in_the_suite_carries_a_well_formed_tag() -> None:
    untagged = [
        test.describe()
        for test in collect_python_property_tests(REPOSITORY_ROOT)
        if test.tag is None or not test.tag.is_well_formed
    ]
    assert not untagged, "property tests without a well-formed tag: " + ", ".join(
        untagged
    )


def test_no_property_number_is_claimed_twice() -> None:
    """One test per property: a number appearing twice means a property was split."""
    owners: dict[int, list[str]] = {}
    for test in collect_python_property_tests(REPOSITORY_ROOT):
        if test.tag is not None:
            owners.setdefault(test.tag.number, []).append(test.describe())
    duplicated = {number: tests for number, tests in owners.items() if len(tests) > 1}
    assert not duplicated, (
        f"property numbers claimed by more than one test: {duplicated}"
    )
