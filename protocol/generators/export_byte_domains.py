# kiro-classification: public
"""Generate `byte_domains.json`, the form of the adversarial byte domains TypeScript reads.

`byte_domains.py` holds the domains and the reasoning for each class. This writes them out for
the TypeScript half, for the same reason `export_catalogue.py` mirrors the schema: one source
of truth, derived rather than maintained twice.

The alternative was a hand-written second copy of the sequences in `byteDomains.ts`, with a test
asserting the two agree. That test is the tell — a check that two copies of a constant match is
a check that a copy should not exist. The domain is the thing Properties 3 and 5 quantify over,
and a byte changed in one language and not the other makes a passing property in that language
mean less than it claims, which is precisely the failure a derived mirror cannot have.

Byte sequences are written as lowercase hex strings. A JSON array of numbers would work and read
worse, and hex survives a diff legibly when a class gains a case.

Run it with `python -m protocol.generators.export_byte_domains`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Final

from protocol.generators.byte_domains import (
    ADVERSARIAL_BYTE_CLASSES,
    CBOR_LENGTH_BOUNDARIES,
    MAX_OUTPUT_BYTES,
    MAX_PATH_COMPONENT_BYTES,
    PATH_SEPARATOR,
    RESERVED_PATH_COMPONENTS,
)

__all__ = ["BYTE_DOMAINS_JSON_PATH", "main", "render", "serialise"]

BYTE_DOMAINS_JSON_PATH: Final = Path(__file__).with_name("byte_domains.json")


def serialise() -> dict[str, Any]:
    """The mirror as plain data, in declaration order."""
    return {
        "adversarialByteClasses": {
            name: [sequence.hex() for sequence in sequences]
            for name, sequences in ADVERSARIAL_BYTE_CLASSES.items()
        },
        "cborLengthBoundaries": list(CBOR_LENGTH_BOUNDARIES),
        "maxOutputBytes": MAX_OUTPUT_BYTES,
        "maxPathComponentBytes": MAX_PATH_COMPONENT_BYTES,
        "pathSeparator": PATH_SEPARATOR,
        "reservedPathComponents": [
            component.hex() for component in RESERVED_PATH_COMPONENTS
        ],
    }


def render() -> str:
    """The exact text `byte_domains.json` should hold, newline-terminated."""
    header = (
        "GENERATED from protocol/generators/byte_domains.py by "
        "protocol/generators/export_byte_domains.py. Do not edit; edit byte_domains.py."
    )
    document = {"$comment": header, **serialise()}
    return json.dumps(document, indent=2, ensure_ascii=False, sort_keys=False) + "\n"


def main() -> None:
    BYTE_DOMAINS_JSON_PATH.write_text(render(), encoding="utf-8")


if __name__ == "__main__":
    main()
