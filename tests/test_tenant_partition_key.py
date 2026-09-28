# kiro-classification: public
"""`pk_for` is the only producer of a Tenant partition key, and nothing else spells the prefix.

The last test in this file is the one that matters: it runs the lint rule over the repository and
fails if any module other than the producer builds the `T#` prefix, imports the prefix constant or
defines a second `pk_for`. The rest establish that the rule detects what it claims to.

**Validates: Requirements 11.2, 11.3**
"""

from __future__ import annotations

import inspect
import textwrap
from dataclasses import FrozenInstanceError

import pytest

from ci.lint_rules import tenant_partition_key as rule
from control_plane.tenancy import (
    MAX_TENANT_ID_LENGTH,
    AuthenticatedPrincipal,
    TenantIdentifierError,
    pk_for,
)
from control_plane.tenancy.partition import TENANT_PARTITION_PREFIX

PRINCIPAL = AuthenticatedPrincipal(
    caller_identity="arn:aws:sts::123456789012:assumed-role/Caller/session",
    tenant_id="tenant-a",
)


def test_pk_for_returns_the_tenant_first_partition_key() -> None:
    assert pk_for(PRINCIPAL) == "T#tenant-a"
    # Nothing precedes the Tenant identifier, which is what lets `dynamodb:LeadingKeys` exist.
    assert pk_for(PRINCIPAL).startswith(TENANT_PARTITION_PREFIX)
    assert pk_for(PRINCIPAL)[len(TENANT_PARTITION_PREFIX) :] == PRINCIPAL.tenant_id


def test_the_authenticated_principal_is_the_only_argument() -> None:
    """No second parameter exists for a request-supplied Tenant identifier to arrive through."""
    parameters = list(inspect.signature(pk_for, eval_str=True).parameters.values())
    assert [parameter.name for parameter in parameters] == ["principal"]
    assert parameters[0].annotation is AuthenticatedPrincipal
    assert parameters[0].default is inspect.Parameter.empty
    assert parameters[0].kind is inspect.Parameter.POSITIONAL_OR_KEYWORD


def test_distinct_tenants_get_distinct_partitions() -> None:
    other = AuthenticatedPrincipal(
        caller_identity=PRINCIPAL.caller_identity, tenant_id="tenant-b"
    )
    assert pk_for(PRINCIPAL) != pk_for(other)


def test_one_caller_identity_cannot_reach_two_partitions() -> None:
    """The principal is frozen, so the Tenant of a request is settled before any handler runs."""
    with pytest.raises(FrozenInstanceError):
        PRINCIPAL.tenant_id = "tenant-b"  # type: ignore[misc]


@pytest.mark.parametrize(
    "tenant_id",
    [
        "",
        "tenant#a",  # Would forge a different key shape.
        "T#tenant-a",  # An already-prefixed value, which would double the prefix.
        "tenant a",
        "tenant\ta",
        "tenant\na",
        "tenant\x00a",
        "t" * (MAX_TENANT_ID_LENGTH + 1),
    ],
)
def test_a_tenant_identifier_that_cannot_become_a_key_is_refused(
    tenant_id: str,
) -> None:
    with pytest.raises(TenantIdentifierError):
        AuthenticatedPrincipal(caller_identity="arn:caller", tenant_id=tenant_id)


def test_an_absent_caller_identity_is_refused() -> None:
    with pytest.raises(TenantIdentifierError):
        AuthenticatedPrincipal(caller_identity="", tenant_id="tenant-a")


@pytest.mark.parametrize(
    "source",
    [
        'PK = "T#" + tenant_id\n',
        'def build(tenant_id):\n    return f"T#{tenant_id}"\n',
        'KEY = "T#tenant-a"\n',
        "from control_plane.tenancy.partition import TENANT_PARTITION_PREFIX\n",
        "import control_plane.tenancy.partition as p\nPK = p.TENANT_PARTITION_PREFIX\n",
        "def pk_for(principal):\n    return principal.tenant_id\n",
    ],
)
def test_the_rule_rejects_a_second_producer(source: str) -> None:
    violations = rule.check_source(source, "control_plane/handlers/sessions.py")
    assert violations, f"no violation reported for: {source!r}"
    assert all(
        violation.path == "control_plane/handlers/sessions.py"
        for violation in violations
    )
    assert violations[0].describe().startswith("control_plane/handlers/sessions.py:")


@pytest.mark.parametrize(
    "source",
    [
        # Prose describing the key structure is documentation, not a producer.
        '"""Session rows live at T#<tenantId>."""\n',
        'def read(pk):\n    """Read one item at T#<tenantId>."""\n    return pk\n',
        "# A comment naming T#<tenantId> is not code.\nPK = None\n",
        # A sort key is what a caller-supplied identifier is allowed to become.
        'SK = f"S#{session_id}"\n',
        # The one partition key outside a Tenant partition.
        'CLAIM_PK = f"H#{provider}#{sandbox}"\n',
    ],
)
def test_the_rule_leaves_documentation_and_sort_keys_alone(source: str) -> None:
    assert rule.check_source(source, "control_plane/state/keys.py") == ()


def test_the_rule_reports_the_line_it_found() -> None:
    source = textwrap.dedent(
        """\
        def handler(event):
            tenant_id = event["tenantId"]
            return f"T#{tenant_id}"
        """
    )
    violations = rule.check_source(source, "control_plane/handlers/sessions.py")
    assert [violation.line for violation in violations] == [3]


def test_the_exemption_is_the_producer_and_the_two_enforcement_modules() -> None:
    """The allow-list is small and every entry exists, so a fourth entry cannot hide in it."""
    assert rule.ALLOWED_MODULES == {rule.PRODUCER_MODULE} | rule.ENFORCEMENT_MODULES
    assert len(rule.ENFORCEMENT_MODULES) == 2
    for relative in rule.ALLOWED_MODULES:
        assert (rule.REPOSITORY_ROOT / relative).is_file(), relative


def test_pk_for_is_the_sole_producer_in_the_repository() -> None:
    violations = rule.check_repository()
    assert not violations, (
        "modules other than the producer build a Tenant partition key: "
        + (", ".join(violation.describe() for violation in violations))
    )
