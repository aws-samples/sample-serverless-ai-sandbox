# Contributing

Contributions welcome. Please open an issue or pull request.

## Development Setup

```bash
uv sync --extra iac   # Install all dependencies including CDK
uv run pytest tests/ -q   # Run the offline test suite
```

## Code Style

This project uses `ruff` for linting and formatting. Run `ruff check` and `ruff format`
before submitting.

## Security

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities.
