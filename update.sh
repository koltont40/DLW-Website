#!/usr/bin/env bash
set -euo pipefail

if [ -n "${DEBUG_INSTALL:-}" ]; then
  set -x
fi

if ! command -v git >/dev/null 2>&1; then
  echo "Error: git is required to pull updates. Install it with 'sudo apt-get install -y git'" >&2
  exit 1
fi

if ! git rev-parse --show-toplevel >/dev/null 2>&1; then
  echo "Error: update.sh must be run from within the repository directory." >&2
  exit 1
fi

if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "Warning: you have local changes. Please commit or stash them before updating." >&2
  exit 1
fi

current_branch=$(git rev-parse --abbrev-ref HEAD)
remote_name=${GIT_REMOTE:-origin}

if ! git ls-remote "$remote_name" &>/dev/null; then
  echo "Error: remote '$remote_name' is not configured or not reachable." >&2
  exit 1
fi

echo "Fetching latest changes from $remote_name/$current_branch..."
git fetch "$remote_name" "$current_branch"

echo "Rebasing your local branch onto $remote_name/$current_branch..."
git pull --rebase --stat "$remote_name" "$current_branch"

if [ -d .venv ]; then
  echo "Updating Python dependencies in existing virtual environment..."
  source .venv/bin/activate
  pip install --upgrade pip >/dev/null
  pip install -r requirements.txt
fi

echo "Repository is up to date."
