# kiro-classification: public
"""Sort keys, the Affinity_Key digest and the one system partition key."""

from __future__ import annotations

import base64
import hashlib

import pytest

from control_plane.state import keys


def test_sort_key_shapes() -> None:
    assert keys.session_sort_key("01JD7Q2M9K") == "S#01JD7Q2M9K"
    assert keys.artifact_sort_key("01JD7Q2M9K", "stdout") == "S#01JD7Q2M9K#A#stdout"
    assert keys.continuation_sort_key("01JD7Q2M9K", 2) == "S#01JD7Q2M9K#C#2"
    assert keys.binding_sort_key("abc") == "K#abc"
    assert keys.CLAIM_SORT_KEY == "CLAIM"


def test_claim_partition_key_names_a_provider_and_a_sandbox() -> None:
    # Uniqueness must hold across Tenants, so this key carries no Tenant identifier (R11.10).
    assert (
        keys.claim_partition_key("lambda-microvms", "sbx-1")
        == "H#lambda-microvms#sbx-1"
    )


def test_affinity_key_digest_is_unpadded_base64url_of_sha256() -> None:
    digest = keys.affinity_key_digest("task-42")
    expected = (
        base64.urlsafe_b64encode(hashlib.sha256(b"task-42").digest())
        .decode()
        .rstrip("=")
    )
    assert digest == expected
    assert "=" not in digest and keys.SEPARATOR not in digest
    # str and bytes forms of the same key agree, so an SDK's encoding choice cannot split a binding.
    assert keys.affinity_key_digest(b"task-42") == digest
    assert keys.affinity_key_digest("task-43") != digest


def test_the_raw_affinity_key_never_appears_in_the_sort_key() -> None:
    affinity_key = "customer-visible-task-name"
    sort_key = keys.binding_sort_key(keys.affinity_key_digest(affinity_key))
    assert affinity_key not in sort_key


@pytest.mark.parametrize(
    "build",
    [
        lambda: keys.session_sort_key("a#b"),
        lambda: keys.artifact_sort_key("a", "b#c"),
        lambda: keys.continuation_sort_key("a#b", 1),
        lambda: keys.binding_sort_key("a#b"),
        lambda: keys.claim_partition_key("p#q", "s"),
        lambda: keys.session_sort_key(""),
    ],
)
def test_an_identifier_cannot_forge_another_key_shape(build) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(ValueError):
        build()


def test_negative_generation_is_rejected() -> None:
    with pytest.raises(ValueError):
        keys.continuation_sort_key("01JD7Q2M9K", -1)


def test_tenant_state_sort_key_orders_by_state_then_creation_time() -> None:
    assert (
        keys.tenant_state_sort_key("RUNNING", 1700000000000) == "RUNNING#1700000000000"
    )


@pytest.mark.parametrize(
    ("sort_key", "kind"),
    [
        ("S#01JD", keys.ItemKind.SESSION),
        ("S#01JD#A#stdout", keys.ItemKind.ARTIFACT_INDEX_ENTRY),
        ("S#01JD#C#3", keys.ItemKind.CONTINUATION),
        ("K#abc", keys.ItemKind.AFFINITY_KEY_BINDING),
        ("CLAIM", keys.ItemKind.SANDBOX_CLAIM),
    ],
)
def test_kind_of_item_classifies_all_five_item_shapes(
    sort_key: str, kind: keys.ItemKind
) -> None:
    assert keys.kind_of_item({"sk": sort_key}) == kind


@pytest.mark.parametrize("item", [{}, {"sk": 7}, {"sk": "Z#1"}, {"sk": "S#a#Z#b"}])
def test_kind_of_item_refuses_an_unrecognised_item(item: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        keys.kind_of_item(item)
