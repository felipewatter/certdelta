#!/usr/bin/env bash
# Legacy bootstrap for creating a NEW repository with the GitHub CLI.
# The public repository is now provisioned; GitHub Actions publishes releases.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
REPO="felipewatter/certdelta"
if ! command -v gh >/dev/null || ! command -v git >/dev/null || ! command -v python >/dev/null; then
  echo "Install git, gh and python before using this legacy bootstrap." >&2
  exit 2
fi
if gh repo view "$REPO" >/dev/null 2>&1; then
  echo "Repository already exists. No changes made. Use GitHub Actions for releases." >&2
  exit 3
fi
python -m pytest -q
python -m ruff check .
python -m pip_audit --strict
python -m build
python scripts/build_release.py
git init -b main
git add .
git commit -m "feat: CertDelta initial release"
gh repo create "$REPO" --public --source . --remote origin --push
echo "GitHub Actions will run the full checks and publish a release on success."
