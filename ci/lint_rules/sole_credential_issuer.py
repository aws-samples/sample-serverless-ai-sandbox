# kiro-classification: public
"""The lint rule that keeps one module the only caller of the credential mint (R6.2, R11.4, R11.5).

The design's issuance claim is that the Control_Plane is the *sole issuer* of a Session connection
credential, and that the port set and the expiry of every credential are derived in one place from
stored Session state. The IAM half of that — only the Control_Plane execution role may mint an
endpoint token — is enforced outside this repository and holds even against code that is wrong. The
half that lives here is narrower and decays silently: someone calls `provider.issue_connection(...)`
directly from a handler or from the orchestration two months from now, picks their own port set,
picks their own TTL, and nothing complains. So it is checked rather than documented.

Two things are rejected outside the issuer module and the provider implementations:

1. a call to :data:`MINT_METHOD`, however it is spelled — bare, through an attribute, or through a
   name bound by an import;
2. a definition of a function or method named :data:`MINT_METHOD`, since a second implementation of
   the mint outside a provider is a second issuer with extra steps.

Reading a name is left alone. `inspect.signature(ComputeProvider.issue_connection)` in the provider
contract test is documentation of the seam's shape, not an issuance, and a rule that forbade naming
the thing it protects would make the contract untestable.

Providers are exempt because a provider *is* the mint: :meth:`ComputeProvider.issue_connection` is
the seam's declaration and each backend's implementation of it. What the rule protects is the layer
above — the decision about scope and lifetime — which has exactly one home.

**What this rule does not claim.** It reads source, so it catches the spellings a person writes and
not a call assembled through `getattr` to defeat it. It does not try to: the boundary that makes a
Sandbox unable to mint its own credential is the IAM permission, and this rule keeps that boundary's
precondition — one derivation of scope and lifetime, in one place — from eroding.

Run it directly:

    uv run python -m ci.lint_rules.sole_credential_issuer

The offline suite runs it too (`tests/test_connection_credentials.py`), which is what puts it in CI.
"""

from __future__ import annotations

import ast
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Final

from ci.lint_rules.tenant_partition_key import (
    REPOSITORY_ROOT,
    Violation,
    iter_python_files,
)

__all__ = [
    "ALLOWED_MODULES",
    "ENFORCEMENT_MODULES",
    "ISSUER_MODULE",
    "MINT_METHOD",
    "PROVIDER_MODULES",
    "check_repository",
    "check_source",
    "main",
]

#: The mint. Named once, here, so the rule and its message cannot disagree about what they protect.
MINT_METHOD: Final = "issue_connection"

#: The sole issuer, as a repository-relative POSIX path.
ISSUER_MODULE: Final = "control_plane/credentials.py"

#: The provider seam and its implementations. A provider *is* the mint; the rule protects the layer
#: that decides what to ask it for. Listed rather than matched by directory so that adding a
#: provider is a reviewed change to this line.
PROVIDER_MODULES: Final = frozenset(
    {
        "control_plane/providers/base.py",
        "control_plane/providers/lambda_microvm.py",
        "control_plane/providers/local_firecracker.py",
        "control_plane/providers/fargate_task.py",
    }
)

#: The modules that exercise the mint in order to establish that it behaves, plus this rule's own
#: test. Stated rather than hidden, and each entry is a file that must exist.
ENFORCEMENT_MODULES: Final = frozenset(
    {
        "ci/lint_rules/sole_credential_issuer.py",
        "tests/test_connection_credentials.py",
        "tests/test_provider_contract.py",
        "tests/test_provider_registry.py",
        "tests/test_local_firecracker_provider.py",
        "tests/test_fargate_task_provider.py",
    }
)

ALLOWED_MODULES: Final = (
    frozenset({ISSUER_MODULE}) | PROVIDER_MODULES | ENFORCEMENT_MODULES
)


def _calls_the_mint(node: ast.Call) -> bool:
    """Whether this call invokes the mint, by attribute or by an imported bare name."""
    target = node.func
    if isinstance(target, ast.Attribute):
        return target.attr == MINT_METHOD
    if isinstance(target, ast.Name):
        return target.id == MINT_METHOD
    return False


def check_source(source: str, path: str) -> tuple[Violation, ...]:
    """Return every violation in `source`, attributed to the relative `path`.

    Exposed rather than private so the test can state the rule against sources it writes, instead of
    only against the repository as it happens to stand.
    """
    module = ast.parse(source, filename=path)
    found: dict[tuple[int, str], Violation] = {}

    def record(line: int, detail: str) -> None:
        found.setdefault((line, detail), Violation(path=path, line=line, detail=detail))

    for node in ast.walk(module):
        if isinstance(node, ast.Call) and _calls_the_mint(node):
            record(
                node.lineno,
                f"{MINT_METHOD} is called outside {ISSUER_MODULE}; call "
                f"ConnectionIssuer.issue(record) instead, which derives the port set and the "
                f"TTL clamp that R11.4 and R11.5 require",
            )
        elif (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == MINT_METHOD
        ):
            record(
                node.lineno,
                f"a {MINT_METHOD} is defined outside the Compute_Provider seam; the sole issuer "
                f"lives in {ISSUER_MODULE}",
            )

    return tuple(found[key] for key in sorted(found))


def check_repository(root: Path = REPOSITORY_ROOT) -> tuple[Violation, ...]:
    """Return every violation in the repository, in file order."""
    violations: list[Violation] = []
    for path in iter_python_files(root):
        relative = path.relative_to(root).as_posix()
        if relative in ALLOWED_MODULES:
            continue
        violations.extend(check_source(path.read_text(encoding="utf-8"), relative))
    return tuple(violations)


def main(argv: Sequence[str] | None = None) -> int:
    """Report violations on stderr and return a process exit status."""
    root = Path(argv[0]).resolve() if argv else REPOSITORY_ROOT
    violations = check_repository(root)
    for violation in violations:
        print(violation.describe(), file=sys.stderr)
    if violations:
        count = len(violations)
        print(
            f"{count} credential issuance violation{'s' if count != 1 else ''}: the sole issuer "
            f"is ConnectionIssuer in {ISSUER_MODULE}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
