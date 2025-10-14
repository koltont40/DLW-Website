#!/usr/bin/env bash
set -euo pipefail

if [ -n "${DEBUG_INSTALL:-}" ]; then
  set -x
fi

missing_packages=()

add_missing() {
  local pkg="$1"
  for existing in "${missing_packages[@]:-}"; do
    if [[ "$existing" == "$pkg" ]]; then
      return
    fi
  done
  missing_packages+=("$pkg")
}

require_command() {
  local cmd="$1"
  local pkg="$2"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    add_missing "$pkg"
  fi
}

require_python_module() {
  local module="$1"
  local pkg="$2"
  if ! python3 -c "import ${module}" >/dev/null 2>&1; then
    add_missing "$pkg"
  fi
}

require_command python3 python3
require_command pip3 python3-pip
require_command certbot certbot

if command -v python3 >/dev/null 2>&1; then
  if ! python3 -m venv --help >/dev/null 2>&1; then
    add_missing "python3-venv"
  fi
else
  add_missing "python3"
fi

if command -v python3 >/dev/null 2>&1; then
  require_python_module sqlite3 libsqlite3-dev
fi

if ((${#missing_packages[@]})); then
  echo "The following system packages are required before installation can continue:" >&2
  printf '  - %s\n' "${missing_packages[@]}" >&2
  if command -v apt-get >/dev/null 2>&1; then
    echo >&2
    echo "Install them with:" >&2
    echo "  sudo apt-get update && sudo apt-get install -y ${missing_packages[*]}" >&2
  fi
  exit 1
fi

if [ ! -d .venv ]; then
  python3 -m venv .venv
fi

source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

python3 -c "from app import init_db; init_db()"

echo
echo "Launching the application on ports 80 (HTTP) and 443 (HTTPS when certificates exist)."
echo "If you encounter a permission error binding to port 80, rerun this script with sudo or grant Python the cap_net_bind_service capability."
if [ -n "${ADMIN_USERNAME:-}" ] && [ -n "${ADMIN_PASSWORD:-}" ]; then
  echo "Configured admin login -> Username: ${ADMIN_USERNAME} (password provided via ADMIN_PASSWORD)"
else
  cat <<'INFO'
No administrator credentials are configured yet.
Set ADMIN_USERNAME and ADMIN_PASSWORD (and optionally ADMIN_EMAIL) before launch to seed the first admin account,
or create an administrator manually using 'python -c "from app import create_app, db, AdminUser; ..."' after initialization.
INFO
fi
echo "Press CTRL+C to stop the server."

exec python3 app.py
