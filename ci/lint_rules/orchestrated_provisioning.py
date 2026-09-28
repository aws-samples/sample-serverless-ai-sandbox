# kiro-classification: public
"""The lint rule that keeps `provision` out of the request handlers (R6.10, R6.11).

R6.11 is a claim about ordering: a Sandbox is provisioned for a Session only after that Session's
Session_Orchestrator execution has been started. The design discharges it structurally rather than
by sequencing two calls carefully — `provision` is moved *inside* the state machine, so there is no
point on the request path at which a Sandbox could come into existence. A Control_Plane handler that
provisioned directly would make the ordering unenforceable, and would hold a request open for the
whole provisioning latency besides.

That is exactly the kind of claim that decays silently. Someone adds a `provider.provision(...)`
call to a handler eighteen months from now because it is the shortest path to a working feature, the
Session row still precedes it, every test still passes, and the guarantee — that every Sandbox which
can exist is governed by a started execution — is quietly gone. So it is checked rather than
documented, in the form `ci/lint_rules/sole_credential_issuer.py` established.

Two things are rejected outside the Compute_Provider seam:

1. a call to :data:`PROVISION_METHOD`, however it is spelled — bare, through an attribute, or
   through a name bound by an import;
2. a definition of a function or method named :data:`PROVISION_METHOD`, since a second
   implementation of provisioning outside a provider is a second way for a Sandbox to appear.

Reading the name is left alone. `tests/test_provider_contract.py` asserts that
:class:`~control_plane.providers.base.ComputeProvider` declares `provision`, which is documentation
of the seam's shape rather than an act of provisioning, and a rule that forbade naming the thing it
protects would make the contract untestable. Prose naming it is likewise untouched: this rule reads
the syntax tree, so a docstring is not a call.

**What the allow-list holds, and why it is a list.** The Session_Orchestrator's task bodies landed
with the Standard state machine, and `control_plane/orchestrator/tasks.py` added itself to
:data:`ORCHESTRATOR_MODULES` in one reviewed line, in the same way adding a Compute_Provider is one
reviewed line in :data:`PROVIDER_MODULES`. Matching by directory instead would let any future module
under a blessed path provision without anyone deciding that it should — which is why the state
machine's own graph, `control_plane/orchestrator/definition.py`, is **not** on the list: it names
provisioning in prose and provisions nothing.

**What this rule does not claim.** It reads source, so it catches the spellings a person writes and
not a call assembled through `getattr` to defeat it. It does not try to. What stops a Sandbox
existing outside an execution in a deployment is that the Control_Plane execution role is not the
role the provisioning task runs as; this rule keeps that boundary's precondition — one place where
provisioning is initiated — from eroding.

Run it directly:

    uv run python -m ci.lint_rules.orchestrated_provisioning

The offline suite runs it too (`tests/test_control_plane_creation.py`), which is what puts it in CI.
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
    "ORCHESTRATOR_MODULES",
    "PROVIDER_MODULES",
    "PROVISION_METHOD",
    "check_repository",
    "check_source",
    "main",
]

#: The provisioning call. Named once, here, so the rule and its message cannot disagree about what
#: they protect.
PROVISION_METHOD: Final = "provision"

#: The Compute_Provider seam and its implementations. A provider *is* provisioning; what the rule
#: protects is who may initiate it.
PROVIDER_MODULES: Final = frozenset(
    {
        "control_plane/providers/base.py",
        "control_plane/providers/lambda_microvm.py",
        "control_plane/providers/local_firecracker.py",
        "control_plane/providers/fargate_task.py",
    }
)

#: The Session_Orchestrator task modules, the only initiators R6.11 permits. An entry here is a
#: reviewed decision that a module runs inside a started execution.
ORCHESTRATOR_MODULES: Final[frozenset[str]] = frozenset(
    {"control_plane/orchestrator/tasks.py"}
)

#: The modules that provision in order to establish that the providers behave. Stated rather than
#: hidden, and every entry is a file that must exist. This rule's own module is not among them: it
#: names the method in prose and in a constant, neither of which it rejects, so it needs no
#: exemption from itself.
ENFORCEMENT_MODULES: Final = frozenset(
    {
        "tests/test_provider_registry.py",
        "tests/test_lambda_microvm_provider.py",
        "tests/test_local_firecracker_provider.py",
        "tests/test_fargate_task_provider.py",
    }
)

ALLOWED_MODULES: Final = PROVIDER_MODULES | ORCHESTRATOR_MODULES | ENFORCEMENT_MODULES


def _calls_provision(node: ast.Call) -> bool:
    """Whether this call provisions, by attribute or by an imported bare name."""
    target = node.func
    if isinstance(target, ast.Attribute):
        return target.attr == PROVISION_METHOD
    if isinstance(target, ast.Name):
        return target.id == PROVISION_METHOD
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
        if isinstance(node, ast.Call) and _calls_provision(node):
            record(
                node.lineno,
                f"{PROVISION_METHOD} is called outside the Session_Orchestrator; R6.11 requires "
                f"every Sandbox to be provisioned inside a started execution, so a handler starts "
                f"the execution and the orchestration provisions",
            )
        elif (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == PROVISION_METHOD
        ):
            record(
                node.lineno,
                f"a {PROVISION_METHOD} is defined outside the Compute_Provider seam; a second "
                f"implementation is a second way for a Sandbox to come into existence",
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
            f"{count} provisioning ordering violation{'s' if count != 1 else ''}: only the "
            f"Session_Orchestrator initiates provisioning, and only inside a started execution",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
