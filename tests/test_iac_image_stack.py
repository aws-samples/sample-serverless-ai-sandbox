# kiro-classification: public
"""`ImageStack` reads the MicroVM image version from CDK context and tags it with a Tenant.

The ``lambda-microvms`` service model is not yet available in boto3, so the stack carries no
resources of its own. These tests verify the context-driven version, the synthesis warning for a
missing version, and the Tenant tagging validation that `control_plane.allocation.tags` owns.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Annotations, Match, Template

from control_plane.allocation.tags import SESSION_TAG_KEY, TENANT_TAG_KEY
from iac.image_stack import (
    DEFAULT_IMAGE_TENANT_ID,
    IMAGE_VERSION_CONTEXT_KEY,
    PLACEHOLDER_IMAGE_VERSION,
    ImageStack,
)


def _synthesise(
    tmp_path: Path, *, context: dict[str, Any] | None = None, **kwargs: Any
) -> tuple[ImageStack, Template]:
    app = cdk.App(outdir=str(tmp_path), context=context or {})
    stack = ImageStack(app, "ImageStack", **kwargs)
    return stack, Template.from_stack(stack)


# ── Image version from CDK context ──────────────────────────────────────────


def test_image_version_is_read_from_cdk_context(tmp_path: Path) -> None:
    stack, _ = _synthesise(
        tmp_path, context={IMAGE_VERSION_CONTEXT_KEY: "img-abc123:3"}
    )
    assert stack.image_version == "img-abc123:3"


def test_missing_image_version_uses_placeholder_and_warns(tmp_path: Path) -> None:
    stack, _template = _synthesise(tmp_path)
    assert stack.image_version == PLACEHOLDER_IMAGE_VERSION
    annotations = Annotations.from_stack(stack)
    annotations.has_warning("*", Match.string_like_regexp("No imageVersion"))


def test_empty_string_image_version_uses_placeholder(tmp_path: Path) -> None:
    stack, _ = _synthesise(tmp_path, context={IMAGE_VERSION_CONTEXT_KEY: ""})
    assert stack.image_version == PLACEHOLDER_IMAGE_VERSION


# ── Tenant tagging ───────────────────────────────────────────────────────────


def test_the_image_carries_the_owning_tenant_and_no_session(tmp_path: Path) -> None:
    stack, _ = _synthesise(tmp_path)
    assert stack.image_tags == {TENANT_TAG_KEY: DEFAULT_IMAGE_TENANT_ID}
    assert SESSION_TAG_KEY not in stack.image_tags


def test_a_named_tenant_reaches_the_image_tags(tmp_path: Path) -> None:
    stack, _ = _synthesise(tmp_path, image_tenant_id="acme")
    assert stack.image_tags == {TENANT_TAG_KEY: "acme"}


@pytest.mark.parametrize("tenant_id", ["", " acme", "ac me", "a#b"])
def test_an_unusable_tenant_identifier_is_refused(
    tmp_path: Path, tenant_id: str
) -> None:
    with pytest.raises(ValueError):
        _synthesise(tmp_path, image_tenant_id=tenant_id)


# ── Empty template ───────────────────────────────────────────────────────────


def test_the_stack_declares_no_resources(tmp_path: Path) -> None:
    _, template = _synthesise(tmp_path)
    assert template.to_json().get("Resources", {}) == {}
