# kiro-classification: public
"""The value space a Sandbox_Protocol message inhabits.

One definition, imported by the codec, the generators and the vector corpus. The alternative —
each of them spelling the same union out — type-checks identically because the alias is
structural, and drifts silently the first time the catalogue admits something new.

The union is closed deliberately. It is exactly what the catalogue's type vocabulary can
declare, so a value outside it is a value no message can carry: no floats, no null, no tags, no
bignums. `encode_value` refuses anything else rather than inventing an encoding for it.
"""

from __future__ import annotations

#: Any value the catalogue's type vocabulary can declare.
type Value = int | bool | str | bytes | list[Value] | dict[Value, Value]

#: One message: the definite-length four-key envelope map of the design's message shape table,
#: keyed by the small unsigned integers `protocol.schema` names. A message *is* that map; there
#: is no wrapper class, because a second representation would be one more thing to keep in step
#: with the catalogue for no gain.
type Message = dict[int, Value]
