#!/usr/bin/env bash
# The whole gate: lint, format, types, tests. Green before every commit.
set -euo pipefail
cd "$(dirname "$0")/.."
uv run ruff check src tests
uv run ruff format --check src tests
uv run mypy
uv run pytest -q
echo "== check: PASS =="
