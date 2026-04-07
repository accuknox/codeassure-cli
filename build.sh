#!/usr/bin/env bash
set -euo pipefail

echo "==> Installing build deps..."
uv pip install --system -e ".[build]"

echo "==> Building standalone binary..."
pyinstaller codeassure.spec --clean

echo ""
echo "Binary ready: dist/codeassure"
echo "Test it: ./dist/codeassure --help"
