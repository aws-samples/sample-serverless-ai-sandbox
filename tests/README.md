<!-- kiro-classification: public -->

# Offline test suite

The suite runs with no deployed AWS resources and no network access (R15.9, R18.17). Loopback stays
reachable, because the offline suite talks to local stubs, a local DynamoDB and the
`local-firecracker` provider.

```sh
make test              # both halves
make test-python       # pytest, from the repository root
make test-typescript   # vitest, in sdk/typescript
```

## Layout

| Path | Contents |
| --- | --- |
| `conftest.py` | Hypothesis profiles and the session-wide network denial |
| `tests/harness/` | The harness itself: the network guard and the property tag form |
| `sdk/typescript/test/setup.ts` | The same two things for fast-check, loaded before every Vitest file |
| `sdk/typescript/test/harness/` | The TypeScript half of the harness |

The root `conftest.py` is at the root deliberately: Python tests live both under `tests/` and next to
the module they cover, and a `conftest.py` one level down would leave the co-located half of the
suite with working egress.

TypeScript property tests live under `sdk/typescript/test/`. Message and byte generators live with
the protocol, in
`protocol/generators/`, so both languages draw from the same source as the codec's schema
catalogue.

## Libraries and iteration counts

Hypothesis for Python and fast-check for TypeScript, both pinned (R15.8) and neither reimplemented.

Every property test runs a minimum of 100 iterations. The codec properties (Properties 1 through 4)
run 1,000, because they are pure functions over byte and integer domains where iterations are nearly
free and the failure modes are subtle. The two counts are declared once and imported rather than
retyped: `MINIMUM_EXAMPLES` and `CODEC_EXAMPLES` from `tests.harness`, `MINIMUM_RUNS` and
`CODEC_RUNS` from `test/harness/config.ts`.

The floor is applied globally — the `default` and `ci` Hypothesis profiles and the fast-check global
configuration — so a property test states an iteration count only when it needs more than the floor:

```python
@settings(max_examples=CODEC_EXAMPLES)
```

`HYPOTHESIS_PROFILE=ci` selects the CI profile, which differs from the default only in switching off
the example database that a clean checkout has nothing to put in.

## Per-property tagging

Each property test carries a comment in the required form, immediately above its decorators, so a
test and its design property cannot drift apart. The first line names the feature and the property
number; the summary may wrap onto further comment lines.

```python
# Feature: aws-serverless-agent-sandbox, Property 3: For any byte sequence, including sequences
# that are not valid UTF-8, carrying that sequence as process output through one serialise and
# deserialise cycle yields a byte sequence identical to the input.
@given(data=output_bytes())
@settings(max_examples=CODEC_EXAMPLES)
def test_process_output_is_byte_exact(data: bytes) -> None: ...
```

TypeScript uses the same form with `//`, above the test declaration:

```ts
// Feature: aws-serverless-agent-sandbox, Property 3: For any byte sequence, including sequences
// that are not valid UTF-8, carrying that sequence as process output through one serialise and
// deserialise cycle yields a byte sequence identical to the input.
test('process output is byte exact', () => {
  fc.assert(fc.property(outputBytes(), (data) => { /* ... */ }), { numRuns: CODEC_RUNS })
})
```

The convention is enforced rather than documented: `tests/harness/test_property_tags.py` and
`sdk/typescript/test/harness/property-tags.test.ts` collect every property test in their language and
fail on one that carries no well-formed tag, on a feature name that is not this feature's, on a
number outside 1 to 44, and on a number claimed by more than one test. Properties 1 through 4 are
stated in both languages, so numbers overlap across languages by design and uniqueness is asserted
per language.

The TypeScript collector is rooted at a directory, and the TypeScript suite has more than one: the
SDK package, plus the halves of the protocol that live beside their Python counterparts, which run
through this package because it holds the repository's only `node_modules`. Each such root carries
the same three checks over itself — `protocol/codec/property-tags.test.ts` is the codec's — so a
property test outside `sdk/typescript/` is not a property test outside the convention. The scan is
per root rather than repository-wide because `protocol/generators/generators.test.ts` drives
fast-check from unit tests that assert the generators' own coverage, correctly carry no tag, and
would be reported as untagged by a wider sweep.

## No network access

Two layers, because either alone would be a claim rather than a guarantee:

1. **In-process.** A session fixture in the root `conftest.py` patches `socket.connect`, `connect_ex`
   and `getaddrinfo`; `test/setup.ts` patches `net.Socket.prototype.connect` and `fetch`. A
   non-loopback destination raises `OutboundNetworkDenied` (`OutboundNetworkDeniedError` in
   TypeScript), and a denied name lookup means a leaked DNS query fails before it leaves the
   process. Both guards are asserted by their own tests rather than trusted.
2. **Around the process.** `ci/deny-egress.sh` rejects every outbound packet except loopback and
   then verifies the rejection holds, so a test reaching the network by a path the guards do not
   patch fails too. It rewrites the host's `OUTPUT` chain, so it runs on a disposable CI runner and
   not on a workstation.

The CI job in `.github/workflows/offline-suite.yml` installs from the committed lock files, runs the
egress denial, and then runs the suite.
