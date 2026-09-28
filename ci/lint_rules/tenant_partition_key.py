# kiro-classification: public
"""The lint rule that keeps `pk_for` the only producer of a Tenant partition key (R11.2, R11.3).

The design's Layer 1 claim is that exactly one function constructs a partition key and that its
only argument is the authenticated principal. A claim of that shape decays silently — someone
writes `f"T#{tenant_id}"` in a handler two months from now and nothing complains — so it is
checked rather than documented. Three things are rejected outside the producer module:

1. a string literal, including an f-string, whose text begins with the Tenant partition prefix;
2. a reference to `TENANT_PARTITION_PREFIX`, since an imported prefix is a second producer with
   extra steps;
3. a second definition of a function named `pk_for`.

The rule reads source, so it catches the spellings a person actually writes. It does not catch a
prefix assembled to defeat it, `"T" + "#"` among them, and it does not try to: the boundary that
makes cross-tenant access impossible is the `dynamodb:LeadingKeys` condition on the per-request
role, which sits in IAM and holds even against a handler that built the wrong key. This rule keeps
that boundary's precondition — one spelling, in one place — from eroding.

Docstrings and comments are left alone. Prose describing the key structure is documentation, and a
rule that forbade naming the thing it protects would be unwritable.

Run it directly, or through `make lint`:

    uv run python -m ci.lint_rules.tenant_partition_key
"""

from __future__ import annotations

import ast
import sys
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, TypeGuard

from control_plane.tenancy.partition import TENANT_PARTITION_PREFIX

__all__ = [
    "ALLOWED_MODULES",
    "ENFORCEMENT_MODULES",
    "PREFIX_CONSTANT_NAME",
    "PRODUCER_FUNCTION",
    "PRODUCER_MODULE",
    "REPOSITORY_ROOT",
    "Violation",
    "check_repository",
    "check_source",
    "iter_python_files",
    "main",
]

REPOSITORY_ROOT: Final = Path(__file__).resolve().parents[2]

#: The sole producer, as a repository-relative POSIX path.
PRODUCER_MODULE: Final = "control_plane/tenancy/partition.py"

PRODUCER_FUNCTION: Final = "pk_for"

PREFIX_CONSTANT_NAME: Final = "TENANT_PARTITION_PREFIX"

#: The two modules that name the prefix in order to forbid it. A rule that cannot spell what it
#: rejects cannot exist, so this exemption is stated rather than hidden, and it is exactly two
#: files long.
ENFORCEMENT_MODULES: Final = frozenset(
    {
        "ci/lint_rules/tenant_partition_key.py",
        "tests/test_tenant_partition_key.py",
    }
)

ALLOWED_MODULES: Final = frozenset({PRODUCER_MODULE}) | ENFORCEMENT_MODULES

_EXCLUDED_DIRECTORIES: Final = frozenset(
    {
        ".git",
        ".venv",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".hypothesis",
        "__pycache__",
        "node_modules",
        "build",
        "dist",
        "cdk.out",
    }
)


@dataclass(frozen=True, slots=True)
class Violation:
    """One rejected construct, located well enough to fix without searching."""

    path: str
    line: int
    detail: str

    def describe(self) -> str:
        return f"{self.path}:{self.line}: {self.detail}"


def _prose_constant_ids(module: ast.Module) -> frozenset[int]:
    """Identify string constants that are documentation rather than values.

    A docstring is a bare string expression statement, wherever it appears, so one rule covers
    module, class and function docstrings without enumerating the node types that carry them.
    """
    prose: set[int] = set()
    for node in ast.walk(module):
        if (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            prose.add(id(node.value))
    return frozenset(prose)


def _leading_literal(node: ast.JoinedStr) -> str:
    """Return the literal text an f-string begins with, before its first interpolation."""
    leading: list[str] = []
    for part in node.values:
        if isinstance(part, ast.Constant) and isinstance(part.value, str):
            leading.append(part.value)
        else:
            break
    return "".join(leading)


def _names_the_prefix_constant(node: ast.AST) -> TypeGuard[ast.Name | ast.Attribute]:
    """Return whether `node` reads the prefix constant, bare or through its module."""
    if isinstance(node, ast.Name):
        return node.id == PREFIX_CONSTANT_NAME
    if isinstance(node, ast.Attribute):
        return node.attr == PREFIX_CONSTANT_NAME
    return False


def check_source(source: str, path: str) -> tuple[Violation, ...]:
    """Return every violation in `source`, attributed to the relative `path`.

    Exposed rather than private so the test can state the rule against sources it writes, instead
    of only against the repository as it happens to stand.
    """
    module = ast.parse(source, filename=path)
    prose = _prose_constant_ids(module)
    found: dict[tuple[int, str], Violation] = {}

    def record(line: int, detail: str) -> None:
        found.setdefault((line, detail), Violation(path=path, line=line, detail=detail))

    literal_detail = (
        f"a string literal builds the Tenant partition key prefix "
        f"{TENANT_PARTITION_PREFIX!r}; call "
        f"{PRODUCER_FUNCTION}(principal) from {PRODUCER_MODULE} instead"
    )
    for node in ast.walk(module):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if id(node) not in prose and node.value.startswith(TENANT_PARTITION_PREFIX):
                record(node.lineno, literal_detail)
        elif isinstance(node, ast.JoinedStr) and _leading_literal(node).startswith(
            TENANT_PARTITION_PREFIX
        ):
            record(node.lineno, literal_detail)
        elif _names_the_prefix_constant(node):
            record(
                node.lineno,
                f"{PREFIX_CONSTANT_NAME} is referenced outside {PRODUCER_MODULE}",
            )
        elif isinstance(node, ast.ImportFrom) and any(
            alias.name == PREFIX_CONSTANT_NAME for alias in node.names
        ):
            record(
                node.lineno,
                f"{PREFIX_CONSTANT_NAME} is imported outside {PRODUCER_MODULE}",
            )
        elif (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == PRODUCER_FUNCTION
        ):
            record(
                node.lineno,
                f"a second {PRODUCER_FUNCTION} is defined; the producer lives in "
                f"{PRODUCER_MODULE}",
            )

    return tuple(found[key] for key in sorted(found))


def iter_python_files(root: Path) -> Iterator[Path]:
    """Yield every Python file under `root`, skipping tool, cache and vendor directories."""
    for path in sorted(root.rglob("*.py")):
        if any(part in _EXCLUDED_DIRECTORIES for part in path.parts):
            continue
        yield path


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
            f"{count} Tenant partition key violation{'s' if count != 1 else ''}: "
            f"{PRODUCER_FUNCTION} in {PRODUCER_MODULE} is the only producer",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
