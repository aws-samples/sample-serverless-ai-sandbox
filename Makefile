# kiro-classification: public

.PHONY: install install-python install-typescript lint format test test-python test-typescript

install: install-python install-typescript

# Installs exactly what the committed lock file records.
install-python:
	uv sync --all-extras --frozen

install-typescript:
	npm ci --prefix sdk/typescript

# Ruff and mypy, then the repository-specific rules no general-purpose linter can express.
# The Tenant partition key rule is also asserted by the offline suite, so CI enforces it too.
lint:
	uv run ruff check .
	uv run mypy .
	uv run python -m ci.lint_rules.tenant_partition_key

format:
	uv run ruff format .

# The offline suite. Both halves deny outbound network access from inside the process
# (R15.9, R18.17); CI additionally removes egress from the machine before running this
# target. See tests/README.md.
test: test-python test-typescript

test-python:
	uv run pytest

test-typescript:
	npm test --prefix sdk/typescript
