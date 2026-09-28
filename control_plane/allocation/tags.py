# kiro-classification: public
"""The Tenant and Session tags R11.7 requires on **every** Sandbox, and their sole producer.

R11.7 has two halves and they are usually conflated. The cost half is that an untagged Sandbox is
one no cost report can attribute to the Tenant that caused it. The operational half is sharper: the
Reaper's only way to reach a Sandbox whose handle was never recorded is
:meth:`~control_plane.providers.base.ComputeProvider.discover`, and `discover` matches on tags. A
Sandbox missing its Tenant and Session tags is therefore not merely unattributable — it is
unreachable by the one component whose job is to find and terminate exactly that Sandbox, and it
runs until its provider-side maximum duration expires.

So the tags are treated as a precondition rather than as metadata:

- :func:`sandbox_tags` is the only place in the Control_Plane that spells either tag key. A
  provisioning task builds a :class:`~control_plane.providers.base.SandboxSpec`'s `tags` from it and
  from nothing else, which is what makes "every Sandbox" a property of one function rather than of
  every call site remembering.
- :func:`require_attribution` refuses a tag map that omits either key, carries either key empty, or
  disagrees with the Tenant and Session it is being checked against. The Sandbox claim ledger calls
  it before it writes a claim, so a Sandbox cannot become the recorded Sandbox of a Session unless
  its tags say the same thing the ledger's own item says.

The disagreement case is the one worth having. Two independent records name the Tenant and the
Session of a Sandbox — the tags on the provider side, the claim item on the State_Store side — and a
Sandbox whose tags name a different Session from its claim would make a cost report and an audit
trail contradict each other with no way to tell which was right. Refusing the claim is the cheap
resolution: nothing has been attributed yet, so there is nothing to reconcile.

**What this module cannot enforce.** It cannot make a tag appear on a Sandbox that was created
without one; only the provisioning call can do that, and the provisioning task is phase 10. What it
provides is the single producer that task builds from and the guard the claim ledger applies, so a
Sandbox provisioned with tags from anywhere else fails at the claim rather than reaching a cost
report unattributed.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final

__all__ = [
    "ATTRIBUTION_TAG_KEYS",
    "SESSION_TAG_KEY",
    "TENANT_TAG_KEY",
    "SandboxNotAttributable",
    "attribution_of",
    "require_attribution",
    "sandbox_tags",
]

#: The owning Tenant identifier (R11.7). Spelled here and nowhere else in the Control_Plane.
TENANT_TAG_KEY: Final = "tenantId"

#: The Session the Sandbox was created for. Not required by R11.7's text, required by the Reaper:
#: a Tenant tag alone would return every Sandbox of a Tenant, and a sweep that cannot narrow to one
#: Session cannot terminate one orphan without risking a live sibling.
SESSION_TAG_KEY: Final = "sessionId"

#: Both attribution keys, in the order a message reports them, so two error strings cannot disagree
#: about which key was missing first.
ATTRIBUTION_TAG_KEYS: Final[tuple[str, str]] = (TENANT_TAG_KEY, SESSION_TAG_KEY)


class SandboxNotAttributable(Exception):
    """A Sandbox's tags do not attribute it to one Tenant and one Session (R11.7).

    Raised by :func:`sandbox_tags` when asked to build such a map and by
    :func:`require_attribution` when handed one. Either way it is refused before a claim is written,
    so an unattributable Sandbox never becomes the recorded Sandbox of a Session.
    """


def _require_tag_value(key: str, value: object) -> str:
    if not isinstance(value, str):
        raise SandboxNotAttributable(f"tag {key!r} is missing or not a string")
    if not value:
        raise SandboxNotAttributable(f"tag {key!r} is empty")
    if value.strip() != value:
        # A tag whose value differs from its trimmed form matches under one provider's filter and
        # not another's, which is the class of defect a Reaper sweep discovers at the worst moment.
        raise SandboxNotAttributable(
            f"tag {key!r} carries leading or trailing whitespace: {value!r}"
        )
    return value


def sandbox_tags(
    *,
    tenant_id: str,
    session_id: str,
    extra: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Return the tag map every Sandbox carries, with the attribution pair always present.

    `extra` carries an operator's own tags — a cost centre, an environment name. It may not contain
    either attribution key: a caller that could override them could produce a Sandbox whose Tenant
    tag names a Tenant that is not paying for it, and silently ignoring such a key would be worse
    than refusing it.

    Raises:
        SandboxNotAttributable: either identifier is empty, is not a string, or `extra` names an
            attribution key.
    """
    tenant = _require_tag_value(TENANT_TAG_KEY, tenant_id)
    session = _require_tag_value(SESSION_TAG_KEY, session_id)
    tags = {TENANT_TAG_KEY: tenant, SESSION_TAG_KEY: session}
    for key, value in (extra or {}).items():
        if key in tags:
            raise SandboxNotAttributable(
                f"extra tags may not override the attribution tag {key!r}"
            )
        tags[key] = value
    return tags


def attribution_of(tags: Mapping[str, str]) -> tuple[str, str]:
    """Return the Tenant and Session a tag map attributes its Sandbox to, in that order.

    Raises:
        SandboxNotAttributable: either attribution tag is absent or unusable.
    """
    return (
        _require_tag_value(TENANT_TAG_KEY, tags.get(TENANT_TAG_KEY)),
        _require_tag_value(SESSION_TAG_KEY, tags.get(SESSION_TAG_KEY)),
    )


def require_attribution(
    tags: Mapping[str, str], *, tenant_id: str, session_id: str
) -> None:
    """Assert that `tags` attribute their Sandbox to exactly this Tenant and this Session.

    Raises:
        SandboxNotAttributable: a tag is absent, unusable, or names a different Tenant or Session.
    """
    tagged_tenant, tagged_session = attribution_of(tags)
    if tagged_tenant != tenant_id:
        raise SandboxNotAttributable(
            f"tag {TENANT_TAG_KEY!r} names {tagged_tenant!r}, not {tenant_id!r}"
        )
    if tagged_session != session_id:
        raise SandboxNotAttributable(
            f"tag {SESSION_TAG_KEY!r} names {tagged_session!r}, not {session_id!r}"
        )
