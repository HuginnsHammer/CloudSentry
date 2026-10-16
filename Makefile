.PHONY: test lint format-check
test:
	pytest
lint:
	ruff check .
format-check:
	ruff format --check .
