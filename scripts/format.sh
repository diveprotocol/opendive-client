#!/bin/bash

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR/.."

echo "--- Running Ruff formatter ---"

echo "Linting and organizing imports..."
ruff check src/opendive/ --select I --fix --silent
ruff check tests/ --select I --fix --silent

echo "Formatting code..."
ruff format src/opendive/
ruff format tests/

echo "--- Code is clean and formatted! ---"
