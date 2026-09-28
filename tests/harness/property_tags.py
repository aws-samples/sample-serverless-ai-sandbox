# kiro-classification: public
"""The per-property tagging comment form the design's Testing Strategy fixes.

Every property test carries a comment in one required form, immediately above its
decorators, so that a test and its design property cannot drift apart:

    # Feature: aws-serverless-agent-sandbox, Property 3: For any byte sequence, including
    # sequences that are not valid UTF-8, carrying that sequence as process output through
    # one serialise and deserialise cycle yields a byte sequence identical to the input.
    @given(data=output_bytes())
    @settings(max_examples=1000)
    def test_process_output_is_byte_exact(data: bytes) -> None:
        ...

A tag's first line carries the feature name and the property number; the summary may wrap
onto further comment lines. This module parses that form and collects it from the suite,
which is what turns the convention into something a test can assert.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Final

__all__ = [
    "FEATURE_NAME",
    "PROPERTY_COUNT",
    "PROPERTY_TAG_PATTERN",
    "PropertyTag",
    "TaggedTest",
    "collect_python_property_tests",
    "iter_python_test_files",
    "parse_property_tag",
]

FEATURE_NAME: Final = "aws-serverless-agent-sandbox"

# The design fixes 44 correctness properties, each implemented by exactly one test.
PROPERTY_COUNT: Final = 44

PROPERTY_TAG_PATTERN: Final = re.compile(
    r"^\s*#\s*Feature:\s(?P<feature>[a-z0-9][a-z0-9-]*),\sProperty\s(?P<number>[1-9][0-9]*):\s(?P<summary>\S.*)$"
)

_CONTINUATION_PATTERN: Final = re.compile(r"^\s*#\s?(?P<text>.*)$")

_EXCLUDED_DIRECTORIES: Final = frozenset(
    {
        ".git",
        ".venv",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".hypothesis",
        "node_modules",
        "build",
        "dist",
        "cdk.out",
    }
)


@dataclass(frozen=True, slots=True)
class PropertyTag:
    """One parsed tag comment."""

    feature: str
    number: int
    summary: str

    @property
    def is_well_formed(self) -> bool:
        return (
            self.feature == FEATURE_NAME
            and 1 <= self.number <= PROPERTY_COUNT
            and bool(self.summary.strip())
        )


@dataclass(frozen=True, slots=True)
class TaggedTest:
    """A property-based test found in the suite, with its tag if it carries one."""

    path: Path
    line: int
    name: str
    tag: PropertyTag | None

    def describe(self) -> str:
        return f"{self.path}:{self.line} {self.name}"


def parse_property_tag(comment_block: list[str]) -> PropertyTag | None:
    """Parse a contiguous run of comment lines into a tag, or None if it is not one."""
    if not comment_block:
        return None
    match = PROPERTY_TAG_PATTERN.match(comment_block[0])
    if match is None:
        return None
    summary_parts = [match.group("summary").strip()]
    for line in comment_block[1:]:
        continuation = _CONTINUATION_PATTERN.match(line)
        if continuation is None:
            break
        summary_parts.append(continuation.group("text").strip())
    return PropertyTag(
        feature=match.group("feature"),
        number=int(match.group("number")),
        summary=" ".join(part for part in summary_parts if part),
    )


def iter_python_test_files(root: Path) -> Iterator[Path]:
    """Yield every Python test module under `root`, skipping tool and vendor directories."""
    for path in sorted(root.rglob("*.py")):
        if any(part in _EXCLUDED_DIRECTORIES for part in path.parts):
            continue
        if path.name.startswith("test_") or path.name.endswith("_test.py"):
            yield path


def _is_given_decorator(node: ast.expr) -> bool:
    target = node.func if isinstance(node, ast.Call) else node
    if isinstance(target, ast.Name):
        return target.id == "given"
    if isinstance(target, ast.Attribute):
        return target.attr == "given"
    return False


def _comment_block_above(lines: list[str], line: int) -> list[str]:
    """Return the contiguous run of comment lines directly above 1-based `line`."""
    block: list[str] = []
    index = line - 2  # The line above, converted to a 0-based index.
    while index >= 0 and lines[index].lstrip().startswith("#"):
        block.append(lines[index])
        index -= 1
    block.reverse()
    return block


def collect_python_property_tests(root: Path) -> list[TaggedTest]:
    """Collect every Hypothesis-driven test under `root` with the tag above it."""
    collected: list[TaggedTest] = []
    for path in iter_python_test_files(root):
        source = path.read_text(encoding="utf-8")
        lines = source.splitlines()
        module = ast.parse(source, filename=str(path))
        for node in ast.walk(module):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not any(
                _is_given_decorator(decorator) for decorator in node.decorator_list
            ):
                continue
            first_decorator_line = min(
                decorator.lineno for decorator in node.decorator_list
            )
            collected.append(
                TaggedTest(
                    path=path,
                    line=first_decorator_line,
                    name=node.name,
                    tag=parse_property_tag(
                        _comment_block_above(lines, first_decorator_line)
                    ),
                )
            )
    return collected
