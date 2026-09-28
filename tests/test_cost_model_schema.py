# kiro-classification: public
"""The Cost_Model schema (R4.3): a valid document per classification, and one invalid per rule.

Every value below is a fixture rather than a price. `.invalid` never resolves (RFC 2606) and no
figure here is retrieved from anywhere; the real ones arrive with tasks 22.4 and 22.5.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any, Final

import pytest
from jsonschema import Draft202012Validator

from tests.harness import REPOSITORY_ROOT

SCHEMA_PATH: Final = REPOSITORY_ROOT / "report" / "cost-model.schema.json"

SCHEMA: Final[dict[str, Any]] = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

# `format` is an annotation by default; asserting it is what makes an impossible date a failure.
VALIDATOR: Final = Draft202012Validator(
    SCHEMA, format_checker=Draft202012Validator.FORMAT_CHECKER
)

FIXTURE_URL: Final = "https://fixture.invalid/pricing-page"
FIXTURE_PACKAGE: Final = "Fixture Pricing Deck"
FIXTURE_RETRIEVAL_DATE: Final = "2000-01-02"
FIXTURE_DOCUMENT_DATE: Final = "2000-01-01"
FIXTURE_STATEMENT: Final = "Fixture statement; the real wording is task 22.5's."

SESSION_SHAPES: Final = (
    "short-burst-60s-active",
    "long-interactive-4h-wall-clock-20pct-active",
    "batch-30m-continuous-active",
)

REQUIRED_LINE_ITEM_FIELDS: Final = (
    "sessionShape",
    "platform",
    "pricingShape",
    "activeCompute",
    "idleOrSuspended",
    "stateStorage",
    "retrievalDate",
)

FALSE_SCHEMA: Final = "false-schema"


def _violations(document: object) -> set[tuple[str, str]]:
    """Every (JSON path, failing keyword) pair reported; a forbidden field reads `false-schema`."""
    return {
        (error.json_path, error.validator or FALSE_SCHEMA)
        for error in VALIDATOR.iter_errors(document)
    }


def _rejected_outright(document: object) -> set[object]:
    """The values a `false` subschema forbids, which names the field that carried them."""
    return {
        error.instance
        for error in VALIDATOR.iter_errors(document)
        if error.validator is None
    }


def _public_line_item(**overrides: Any) -> dict[str, Any]:
    item: dict[str, Any] = {
        "sessionShape": "short-burst-60s-active",
        "platform": "Fixture Platform A",
        "pricingShape": "per-second-compute-plus-snapshot-storage",
        "activeCompute": {"amountUsd": 1.0},
        "idleOrSuspended": {"amountUsd": 0.25},
        "stateStorage": {"amountUsd": 0.5},
        "retrievalDate": FIXTURE_RETRIEVAL_DATE,
        "sourceUrl": FIXTURE_URL,
    }
    return item | overrides


def _gpu_line_item(**overrides: Any) -> dict[str, Any]:
    three_component: dict[str, Any] = {
        "perRequestUsd": 1.0,
        "computeManagementFeePercentOfEc2OnDemandDedicatedHost": 2.0,
        "ec2InstanceUsd": 3.0,
    }
    item: dict[str, Any] = {
        "sessionShape": "batch-30m-continuous-active",
        "platform": "Fixture GPU Platform",
        "pricingShape": "lmi-gpu-three-component",
        "activeCompute": dict(three_component),
        "idleOrSuspended": dict(three_component),
        "stateStorage": "unpriced",
        "retrievalDate": FIXTURE_RETRIEVAL_DATE,
        "packageName": FIXTURE_PACKAGE,
        "documentDate": FIXTURE_DOCUMENT_DATE,
    }
    return item | overrides


def _public_document(*line_items: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "classification": "public",
        "lineItems": list(line_items) or [_public_line_item()],
    }
    return document | overrides


def _confidential_document(
    *line_items: dict[str, Any], **overrides: Any
) -> dict[str, Any]:
    document: dict[str, Any] = {
        "classification": "confidential",
        "perSecondRateNotComparable": FIXTURE_STATEMENT,
        "idleFromContinuousMinimumEnvironment": FIXTURE_STATEMENT,
        "lineItems": list(line_items) or [_gpu_line_item()],
    }
    return document | overrides


def _nodes(node: object) -> Iterator[tuple[str, object]]:
    if isinstance(node, dict):
        for key, value in node.items():
            yield key, value
            yield from _nodes(value)
    elif isinstance(node, list):
        for value in node:
            yield from _nodes(value)


def test_the_schema_is_a_valid_draft_2020_12_schema() -> None:
    Draft202012Validator.check_schema(SCHEMA)


def test_the_schema_resolves_with_no_network_access() -> None:
    # R15.9: the suite denies egress, so a remote `$schema` or `$ref` would not merely be
    # slow, it would fail. Neither is present, which is why the dialect is chosen above.
    assert "$schema" not in SCHEMA
    references = [value for key, value in _nodes(SCHEMA) if key == "$ref"]
    assert references
    assert all(isinstance(ref, str) and ref.startswith("#") for ref in references)


def test_a_public_document_validates() -> None:
    assert _violations(_public_document()) == set()


def test_a_confidential_document_validates() -> None:
    assert _violations(_confidential_document()) == set()


def test_a_document_may_carry_the_classification_marker_every_json_file_carries() -> None:
    document = _public_document()
    document["$comment"] = "kiro-classification: public"
    assert _violations(document) == set()


def test_all_three_named_session_shapes_are_admissible() -> None:
    # R4.1's three shapes, and no fourth: the enum is the list of names.
    document = _public_document(
        *(_public_line_item(sessionShape=shape) for shape in SESSION_SHAPES)
    )
    assert _violations(document) == set()


def test_an_unnamed_session_shape_is_rejected() -> None:
    document = _public_document(_public_line_item(sessionShape="medium-burst-90s"))
    assert ("$.lineItems[0].sessionShape", "enum") in _violations(document)


@pytest.mark.parametrize("field", REQUIRED_LINE_ITEM_FIELDS)
def test_a_line_item_missing_a_required_field_is_rejected(field: str) -> None:
    # R4.2: the three costs are separate fields of one line item, so none can go missing
    # while the shape-and-platform pair still validates.
    item = {k: v for k, v in _public_line_item().items() if k != field}
    assert ("$.lineItems[0]", "required") in _violations(_public_document(item))


def test_a_document_needs_at_least_one_line_item() -> None:
    assert ("$.lineItems", "minItems") in _violations(_public_document(lineItems=[]))


def test_an_undeclared_line_item_field_is_rejected() -> None:
    document = _public_document(_public_line_item(estimatedCost={"amountUsd": 1.0}))
    assert (
        "$.lineItems[0]",
        "additionalProperties",
    ) in _violations(document)


def test_an_impossible_retrieval_date_is_rejected() -> None:
    document = _public_document(_public_line_item(retrievalDate="2000-13-45"))
    assert ("$.lineItems[0].retrievalDate", "format") in _violations(document)


def test_a_negative_amount_is_rejected() -> None:
    document = _public_document(_public_line_item(activeCompute={"amountUsd": -1.0}))
    assert ("$.lineItems[0].activeCompute", "oneOf") in _violations(document)


# --- R4.4 and R4.8: the citation form is an either/or, decided by the classification ---


def test_a_public_line_item_must_carry_a_source_url() -> None:
    item = {k: v for k, v in _public_line_item().items() if k != "sourceUrl"}
    assert ("$.lineItems[0]", "required") in _violations(_public_document(item))


def test_a_public_line_item_may_not_carry_the_confidential_citation_form() -> None:
    document = _public_document(
        _public_line_item(
            packageName=FIXTURE_PACKAGE, documentDate=FIXTURE_DOCUMENT_DATE
        )
    )
    assert ("$.lineItems[0]", FALSE_SCHEMA) in _violations(document)
    # Both forbidden fields are named, not just the first one found.
    assert _rejected_outright(document) == {FIXTURE_PACKAGE, FIXTURE_DOCUMENT_DATE}


def test_a_confidential_line_item_must_carry_a_package_name_and_document_date() -> None:
    for field in ("packageName", "documentDate"):
        item = {k: v for k, v in _gpu_line_item().items() if k != field}
        assert ("$.lineItems[0]", "required") in _violations(
            _confidential_document(item)
        ), field


def test_a_confidential_line_item_may_not_carry_a_source_url() -> None:
    document = _confidential_document(_gpu_line_item(sourceUrl=FIXTURE_URL))
    assert ("$.lineItems[0]", FALSE_SCHEMA) in _violations(document)
    assert _rejected_outright(document) == {FIXTURE_URL}


def test_a_source_url_that_is_not_one_is_rejected() -> None:
    document = _public_document(_public_line_item(sourceUrl="internal deck, page 4"))
    assert ("$.lineItems[0].sourceUrl", "pattern") in _violations(document)


# --- R4.6: `unpriced` is a value in place of a figure, never a flag beside one ---


def test_unpriced_stands_alone_as_a_cost() -> None:
    document = _public_document(
        _public_line_item(activeCompute="unpriced", stateStorage="unpriced")
    )
    assert _violations(document) == set()


@pytest.mark.parametrize(
    "cost",
    [
        {"unpriced": True, "amountUsd": 1.0},
        {"amountUsd": 1.0, "unpriced": "unpriced"},
        {"unpriced": True},
    ],
    ids=["flag-beside-a-figure", "figure-beside-a-flag", "flag-alone"],
)
def test_unpriced_cannot_be_written_as_a_field_alongside_a_figure(
    cost: dict[str, Any],
) -> None:
    # R4.6 records an unpriced line item rather than estimating it. The value position holds
    # either the literal or an object of figures, so there is no key an estimate fits into.
    document = _public_document(_public_line_item(activeCompute=cost))
    assert ("$.lineItems[0].activeCompute", "oneOf") in _violations(document)


def test_unpriced_state_storage_cannot_carry_a_figure() -> None:
    document = _public_document(
        _public_line_item(stateStorage={"unpriced": True, "amountUsd": 0.5})
    )
    assert ("$.lineItems[0].stateStorage", "oneOf") in _violations(document)


def test_a_misspelt_unpriced_is_rejected() -> None:
    document = _public_document(_public_line_item(idleOrSuspended="not priced"))
    assert ("$.lineItems[0].idleOrSuspended", "oneOf") in _violations(document)


# --- R4.9, R4.10 and R4.11: the LMI_GPU pricing shape is a distinct shape ---


def test_a_single_figure_cannot_stand_in_for_the_three_component_shape() -> None:
    document = _confidential_document(_gpu_line_item(activeCompute={"amountUsd": 1.0}))
    assert ("$.lineItems[0].activeCompute", "oneOf") in _violations(document)


@pytest.mark.parametrize(
    "component",
    [
        "perRequestUsd",
        "computeManagementFeePercentOfEc2OnDemandDedicatedHost",
        "ec2InstanceUsd",
    ],
)
def test_the_three_component_shape_keeps_all_three_components(component: str) -> None:
    # R4.9: three separate components, so a line item cannot quietly drop one.
    active = _gpu_line_item()["activeCompute"]
    del active[component]
    document = _confidential_document(_gpu_line_item(activeCompute=active))
    assert ("$.lineItems[0].activeCompute", "oneOf") in _violations(document)


def test_the_three_component_shape_admits_no_aggregate_figure() -> None:
    # R4.10 made structural: the object has no field a per-second rate could be written in.
    active = _gpu_line_item()["activeCompute"] | {"amountUsd": 6.0}
    document = _confidential_document(_gpu_line_item(activeCompute=active))
    assert ("$.lineItems[0].activeCompute", "oneOf") in _violations(document)


@pytest.mark.parametrize(
    "statement",
    ["perSecondRateNotComparable", "idleFromContinuousMinimumEnvironment"],
)
def test_a_gpu_line_item_requires_both_statements_about_its_shape(
    statement: str,
) -> None:
    document = _confidential_document()
    del document[statement]
    assert ("$", "required") in _violations(document)


def test_a_document_without_a_gpu_line_item_needs_neither_statement() -> None:
    assert "perSecondRateNotComparable" not in _public_document()
    assert _violations(_public_document()) == set()


# --- R4.5 and R4.7 ---


def test_the_assumptions_are_stated_together_or_not_at_all() -> None:
    complete = {
        "microVmBaselineSize": FIXTURE_STATEMENT,
        "snapshotSize": FIXTURE_STATEMENT,
        "requestVolume": FIXTURE_STATEMENT,
    }
    assert _violations(_public_document(assumptions=complete)) == set()
    partial = {k: v for k, v in complete.items() if k != "snapshotSize"}
    assert ("$.assumptions", "required") in _violations(
        _public_document(assumptions=partial)
    )


def test_omitted_components_names_at_least_one_component() -> None:
    # R4.7: a figure computed from some of the components names the ones it left out.
    named = _public_line_item(
        activeCompute={"amountUsd": 1.0, "omittedComponents": ["a fixture component"]}
    )
    assert _violations(_public_document(named)) == set()
    empty = _public_line_item(activeCompute={"amountUsd": 1.0, "omittedComponents": []})
    assert ("$.lineItems[0].activeCompute", "oneOf") in _violations(
        _public_document(empty)
    )
