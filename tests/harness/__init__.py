# kiro-classification: public
"""The offline test harness (R15.9).

Two things live here, and nothing else: the guard that denies outbound network access, and
the per-property tagging comment form the design's Testing Strategy fixes.

Iteration counts come from the design: every property test runs a minimum of 100
iterations, and the codec properties (Properties 1 through 4) run 1,000, because they are
pure functions over byte and integer domains where iterations are nearly free. Codec tests
import `CODEC_EXAMPLES` rather than repeating the number.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

from tests.harness.network import NetworkGuard, OutboundNetworkDenied, is_loopback_host
from tests.harness.property_tags import (
    FEATURE_NAME,
    PROPERTY_COUNT,
    PROPERTY_TAG_PATTERN,
    PropertyTag,
    TaggedTest,
    collect_python_property_tests,
    iter_python_test_files,
    parse_property_tag,
)

MINIMUM_EXAMPLES: Final = 100
CODEC_EXAMPLES: Final = 1_000

REPOSITORY_ROOT: Final = Path(__file__).resolve().parents[2]

__all__ = [
    "CODEC_EXAMPLES",
    "FEATURE_NAME",
    "MINIMUM_EXAMPLES",
    "PROPERTY_COUNT",
    "PROPERTY_TAG_PATTERN",
    "REPOSITORY_ROOT",
    "NetworkGuard",
    "OutboundNetworkDenied",
    "PropertyTag",
    "TaggedTest",
    "collect_python_property_tests",
    "is_loopback_host",
    "iter_python_test_files",
    "parse_property_tag",
]
