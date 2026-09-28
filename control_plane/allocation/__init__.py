# kiro-classification: public
"""Sandbox allocation eligibility and the claim ledger (R11.1, R11.7, R11.10, R11.12, R11.13).

One Sandbox is allocated to at most one Session, ever. This package is where that sentence stops
being a claim and becomes a conditional write.

Three modules, each holding one thing:

- :mod:`control_plane.allocation.ledger` — the claim item, written under
  `attribute_not_exists(pk)`, so exclusivity is the store's answer rather than a comparison the
  Control_Plane performs. It also owns what happens to the loser: the Sandbox a losing caller
  provisioned is terminated inside the failing call, before :class:`SandboxAlreadyClaimed` reaches
  the caller.
- :mod:`control_plane.allocation.quarantine` — the closed subset of denial reasons that make a
  Sandbox ineligible (R11.12), and the recorded-failure trigger beside it (R11.13), kept
  distinguishable after the fact.
- :mod:`control_plane.allocation.tags` — the Tenant and Session tags every Sandbox carries
  (R11.7), and the guard the ledger applies before it will record a claim.

**What is not here.** No provisioning: allocation observes a Sandbox that already exists and
records the fact, and `provision` lives behind the Compute_Provider seam under a lint rule that
keeps it there. No credential issuance: `control_plane/credentials.py` is the sole issuer, also
under a lint rule. Lifecycle reconciliation and binding expiry are their own task. The claim item
carries no TTL attribute, because TTL expiry reaching it would delete the only record that a
billable Sandbox was ever allocated.
"""

from control_plane.allocation.ledger import (
    ClaimConditionFailed,
    ClaimItemStore,
    DuplicateTermination,
    SandboxAlreadyClaimed,
    SandboxClaimLedger,
    SandboxNotClaimed,
    SandboxTerminator,
    claim_key_for,
    is_allocatable,
)
from control_plane.allocation.quarantine import (
    CIRCUMVENTION_REASONS,
    NON_CIRCUMVENTION_REASONS,
    SESSION_FAILURE_REASON,
    DenialIsNotCircumvention,
    DenialReason,
    Quarantine,
    QuarantineReasonUnrecognised,
    QuarantineTrigger,
    is_circumvention,
)
from control_plane.allocation.tags import (
    ATTRIBUTION_TAG_KEYS,
    SESSION_TAG_KEY,
    TENANT_TAG_KEY,
    SandboxNotAttributable,
    attribution_of,
    require_attribution,
    sandbox_tags,
)

__all__ = [
    "ATTRIBUTION_TAG_KEYS",
    "CIRCUMVENTION_REASONS",
    "NON_CIRCUMVENTION_REASONS",
    "SESSION_FAILURE_REASON",
    "SESSION_TAG_KEY",
    "TENANT_TAG_KEY",
    "ClaimConditionFailed",
    "ClaimItemStore",
    "DenialIsNotCircumvention",
    "DenialReason",
    "DuplicateTermination",
    "Quarantine",
    "QuarantineReasonUnrecognised",
    "QuarantineTrigger",
    "SandboxAlreadyClaimed",
    "SandboxClaimLedger",
    "SandboxNotAttributable",
    "SandboxNotClaimed",
    "SandboxTerminator",
    "attribution_of",
    "claim_key_for",
    "is_allocatable",
    "is_circumvention",
    "require_attribution",
    "sandbox_tags",
]
