# kiro-classification: public
"""Resolving a caller-supplied Session identifier, and why there is only one outcome (R6.9).

This module is the code half of the design's Layer 3, indistinguishability from absence. It has one
function of consequence and the interesting thing about it is what it does **not** contain.

There is **no branch for "the Session exists but belongs to another Tenant"**. Not one that returns
not-found, not one that logs, not one that increments a counter. The read is issued against
`pk_for(principal)`, the caller's own partition and the only partition the per-request credentials
can address at all, so a row in a different Tenant's partition is not something this code sees and
declines to mention — it is something the operation never returns. That is a stronger statement than
a comparison would be, and it is why the two cases R6.9 requires to be indistinguishable are
literally the same operation with the same duration and the same single log-free path.

A tenant comparison on the returned record would therefore be worse than redundant. It would create
the second branch this design exists to avoid, and with it a measurable difference — in timing, in
which counter moved, in what a future log line said — between a Session that exists elsewhere and
one that never existed. Confinement is structural: `pk_for` is the sole producer of the partition
key (Layer 1, with a lint rule keeping it so) and the per-request `SessionDataAccessRole` pins
`dynamodb:LeadingKeys` to that one value (Layer 2), so a handler that somehow built another Tenant's
key receives `AccessDenied` from DynamoDB rather than a row.

Three inputs collapse onto the identical response, and the third is the one worth naming:

1. A well-formed identifier that never existed anywhere — no item.
2. A well-formed identifier belonging to another Tenant — no item, for the reason above.
3. An identifier that is not well formed at all, such as one carrying the key separator. Refused
   before the read, and mapped to the same response rather than to a `400`. A malformed identifier
   cannot name an existing Session, so not-found is true; and answering it differently would hand a
   prober one bit for free by telling them which of their guesses were even addressable.

Session identifiers are 128-bit random ULIDs, so existence cannot be probed by enumeration either.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol

from control_plane.api.errors import SessionNotFound
from control_plane.state.keys import ItemShapeError, session_sort_key
from control_plane.state.records import SessionRecord
from control_plane.tenancy import AuthenticatedPrincipal, pk_for

__all__ = ["SessionLookup", "resolve_session"]


class SessionLookup(Protocol):
    """The one read a handler performs to turn an identifier into a record.

    A structural type, so the offline suite drives every path here against an in-memory store with
    no deployed resources and no network, and so boto3 stays out of the import graph of the modules
    that only need the shape.

    The read is **strongly consistent**. Eventually consistent is not an acceptable substitute:
    `GetSession` issued immediately after `CreateSession` returned would be able to miss a row that
    exists, which is a spurious not-found — and a not-found that is sometimes wrong is worse than
    one that is always right, because a caller cannot tell the two apart either.
    """

    def read_session(
        self, *, partition_key: str, sort_key: str
    ) -> Mapping[str, Any] | None:
        """Return the item at this key, or `None` when there is no item at it."""
        ...


def resolve_session(
    principal: AuthenticatedPrincipal, session_id: str, lookup: SessionLookup
) -> SessionRecord:
    """Return the Session this caller named, or raise the fixed not-found.

    The partition key comes from the principal and the sort key from the identifier, which is the
    whole of the asymmetry that makes this safe: a caller-supplied value can only ever become a
    sort key, never a partition key.

    A stored item that does not parse is deliberately *not* absorbed into the not-found response. An
    item in the caller's own partition that has the wrong shape is a defect in this system, not a
    question about somebody else's Session, and silently reporting it as not-found would hide a bug
    behind a security response.
    """
    try:
        sort_key = session_sort_key(session_id)
    except ItemShapeError:
        raise SessionNotFound from None

    item = lookup.read_session(partition_key=pk_for(principal), sort_key=sort_key)
    if item is None:
        raise SessionNotFound
    return SessionRecord.from_item(item)
