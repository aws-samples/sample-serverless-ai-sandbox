# kiro-classification: public
"""Every per-Session unique value, generated inside the `/run` hook and nowhere else (R7.12).

R7.12 is one requirement with one adversary: a value captured while the MicroVM image was built
would be identical in every Sandbox started from that image version. So the requirement is not
"generate good values", it is "generate them *here*, at this moment, in this process" — and the
mechanism is where the generation happens rather than how strong it is.

That has three consequences this module is shaped by, and all three are things a reader should be
able to check by looking:

1. **No value is a module-level constant, a class attribute or a default argument.** A default
   argument would be the subtlest way to fail this requirement: Python evaluates it once, when
   the module is imported, and the runtime is imported during the image build. The only way a
   value gets into a `SessionValues` is `generate()` calling `secrets` while `/run` is executing.
2. **`secrets`, not `random`.** `random` is a Mersenne Twister seeded from the clock or from
   entropy that a snapshot can preserve, and a Sandbox resumed from a snapshot would replay the
   same sequence. `secrets` draws from the operating system's CSPRNG.
3. **Generated exactly once per Sandbox.** The readiness gate refuses a second `/run` for this
   reason — `runtime.readiness` says so where the transition is absent — and
   `runtime.lifecycle` publishes one `SessionValues` object once. Regenerating them mid-Session
   would invalidate every handle already issued under the old key.

The design names the values: the Family B private key and its certificate signing request, the
process-handle HMAC key, and the Runtime instance identifier used in log stream naming.

## What is generated here, and what is deliberately not

`egress_private_key` is the Family B private key material. It is generated inside the MicroVM and
never leaves it, which is the property the design's Family B section rests on ("the Runtime
generates a keypair *inside the MicroVM* and never transmits the private key").

The **certificate signing request is not built here**, and that is a scope boundary rather than an
omission. A CSR is an X.509 structure, so producing one means an asymmetric algorithm, a public
key derived from this key material, and DER encoding — none of which the standard library offers
and none of which should be hand-rolled. It also means the bootstrap exchange with the signing
endpoint, which is the Egress_Controller's, and the certificate lifetime clamped to the Session
remainder, which is the orchestrator's. The Family B egress identity has its own task for exactly
that reason. What R7.12 asks of the `/run` hook is that the per-Session secret exist and be born
here, and that is what this module does; the identity built on top of it is assembled elsewhere
from this value.

`process_handle_key` is the process-handle HMAC key. `runtime.process` currently mints each
background handle from `secrets.token_hex` directly, which is already unguessable and already
per-Sandbox, so this key is generated and published rather than wired in: signing handles with it
would change how `ProcessManager` mints them, and that is the process manager's surface, not this
hook's. The value being per-Session is what R7.12 asks for and what a test can check.

`instance_id` identifies this runtime process in log stream names. It is text, and hex rather than
raw bytes, because a log stream name is a string in a naming convention and a value that has to be
escaped before it can be logged is the wrong shape for the one place it is used.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Final

__all__ = [
    "EGRESS_PRIVATE_KEY_BYTES",
    "INSTANCE_ID_BYTES",
    "PROCESS_HANDLE_KEY_BYTES",
    "SessionValues",
]

#: 16 bytes rendered as 32 hex characters. An identifier, not a secret: it appears in log stream
#: names, so its job is to be unique across Sandboxes rather than unguessable.
INSTANCE_ID_BYTES: Final = 16

#: 32 bytes, which is the block size of SHA-256 truncated to its output length and the size
#: RFC 2104 recommends for an HMAC key: a longer key is hashed down to it and a shorter one is
#: padded, so 32 is the point past which nothing is gained.
PROCESS_HANDLE_KEY_BYTES: Final = 32

#: 32 bytes of private key material. The width of an Ed25519 seed and of a P-256 private scalar,
#: so the eventual choice of algorithm in the Family B identity task is not pre-empted by it.
EGRESS_PRIVATE_KEY_BYTES: Final = 32


@dataclass(frozen=True, slots=True)
class SessionValues:
    """The per-Session unique values one Sandbox generated during its own `/run` hook.

    Frozen, so that a value cannot be replaced after the handles and identities derived from it
    have been issued. There is no default for any field and no zero value: an empty
    `SessionValues` would be a plausible-looking object carrying no per-Session identity at all,
    which is precisely the state R7.12 exists to make unreachable.
    """

    instance_id: str
    process_handle_key: bytes
    egress_private_key: bytes

    @classmethod
    def generate(cls) -> SessionValues:
        """Draw a fresh set from the operating system's CSPRNG.

        Called from inside the `/run` hook, once. Every call returns a distinct set: nothing is
        cached here, and a caller wanting the same values twice holds the object rather than
        calling this again.
        """
        return cls(
            instance_id=secrets.token_hex(INSTANCE_ID_BYTES),
            process_handle_key=secrets.token_bytes(PROCESS_HANDLE_KEY_BYTES),
            egress_private_key=secrets.token_bytes(EGRESS_PRIVATE_KEY_BYTES),
        )

    def __repr__(self) -> str:
        """Report the identifier and withhold the two secrets.

        The default dataclass `repr` would render the private key material, and a `repr` reaches
        places a deliberate log line does not: an unhandled exception's traceback, a test failure
        report, a debugger transcript. The Family B key is the one value in this object whose
        whole premise is that it never leaves the MicroVM, and a traceback is a way out.
        """
        return f"SessionValues(instance_id={self.instance_id!r}, secrets=withheld)"
