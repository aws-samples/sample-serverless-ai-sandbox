# kiro-classification: public
"""Repository-specific lint rules that no general-purpose linter can express.

Each rule is a module with a `check_repository` function and a `main` entry point, so `make lint`
runs it and the offline suite asserts the same rule over the same tree.
"""
