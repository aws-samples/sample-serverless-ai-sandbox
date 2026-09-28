# kiro-classification: public
"""Generate `catalogue.json`, the form of the schema catalogue the TypeScript half reads.

`messages.yaml` stays the single schema source (R8.1). The TypeScript package pins `cbor-x`,
`fast-check`, `typescript` and `vitest` and no YAML parser, and the choice made here is to
generate a JSON mirror rather than to pin one:

- A parser would be a runtime dependency of the *generators*, added for a document that is read
  once and never changes at run time, and it would have to be kept in step with PyYAML's view
  of the same document — two parsers, one schema, and any disagreement between them is a
  cross-language wire bug that the vector corpus would have to catch late.
- The mirror is *derived*, not maintained: it is written from the already-validated `Catalogue`,
  so it cannot carry a shape the loader would have rejected, and `test_generators.py` asserts
  the committed file is what this module would write today. A stale mirror fails the offline
  suite rather than silently narrowing the TypeScript generators.

The mirror is the normalised catalogue, not the raw document: optional keys are omitted rather
than written as null, so the TypeScript reader needs the same presence checks the Python one
does and no defaulting rules of its own. Integer range bounds are written as decimal strings,
because a JSON number cannot carry the full CBOR unsigned range without loss in a JavaScript
reader.

Run it with `python -m protocol.generators.export_catalogue`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Final

from protocol.schema import Catalogue, Field, TypeSpec, load_catalogue

__all__ = ["CATALOGUE_JSON_PATH", "main", "render", "serialise"]

CATALOGUE_JSON_PATH: Final = Path(__file__).with_name("catalogue.json")


def _spec(spec: TypeSpec) -> dict[str, Any]:
    rendered: dict[str, Any] = {"type": str(spec.kind)}
    if spec.range is not None:
        # Decimal strings, not JSON numbers. The envelope's `v` admits the full CBOR unsigned
        # range, and 18446744073709551615 does not survive `JSON.parse` — it becomes
        # 18446744073709552000, which is both wrong and silently so. Strings are read as `int`
        # in Python and `BigInt` in TypeScript, and both readings are exact.
        rendered["range"] = {"min": str(spec.range.min), "max": str(spec.range.max)}
    if spec.enum is not None:
        rendered["enum"] = list(spec.enum)
    if spec.carries is not None:
        rendered["carries"] = str(spec.carries)
    if spec.items is not None:
        rendered["items"] = _spec(spec.items)
    if spec.keys is not None:
        rendered["keys"] = _spec(spec.keys)
    if spec.values is not None:
        rendered["values"] = _spec(spec.values)
    if spec.fields:
        rendered["fields"] = [_field(field) for field in spec.fields]
    return rendered


def _field(field: Field) -> dict[str, Any]:
    rendered: dict[str, Any] = {
        "key": field.key,
        "name": field.name,
        **_spec(field.spec),
    }
    if field.optional:
        rendered["optional"] = True
    return rendered


def serialise(catalogue: Catalogue) -> dict[str, Any]:
    """The mirror as plain data, in catalogue order."""
    return {
        "schemaVersion": catalogue.schema_version,
        "protocol": {
            "version": catalogue.protocol_version,
            "supportedMin": catalogue.supported_min,
            "supportedMax": catalogue.supported_max,
        },
        "envelope": {"fields": [_field(field) for field in catalogue.envelope]},
        "messages": [
            {
                "t": message.t,
                "direction": str(message.direction),
                "requirements": list(message.requirements),
                "body": [_field(field) for field in message.body],
            }
            for message in catalogue.messages.values()
        ],
    }


def render(catalogue: Catalogue | None = None) -> str:
    """The exact text `catalogue.json` should hold, newline-terminated."""
    resolved = catalogue if catalogue is not None else load_catalogue()
    header = (
        "GENERATED from protocol/messages.yaml by "
        "protocol/generators/export_catalogue.py. Do not edit; edit messages.yaml."
    )
    document = {"$comment": header, **serialise(resolved)}
    return json.dumps(document, indent=2, ensure_ascii=False, sort_keys=False) + "\n"


def main() -> None:
    CATALOGUE_JSON_PATH.write_text(render(), encoding="utf-8")


if __name__ == "__main__":
    main()
