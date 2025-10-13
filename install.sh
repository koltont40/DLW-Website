#!/usr/bin/env bash
set -euo pipefail

if [ -n "${DEBUG_INSTALL:-}" ]; then
  set -x
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3 is required. Please install it and re-run this script." >&2
  exit 1
fi

if ! command -v pip3 >/dev/null 2>&1; then
  echo "python3-pip is required. Install it with 'sudo apt install python3-pip'." >&2
  exit 1
fi

if [ ! -d .venv ]; then
  python3 -m venv .venv
fi

source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

python -c "from app import init_db; init_db()"

export FLASK_APP=app
export FLASK_RUN_HOST=0.0.0.0
export FLASK_RUN_PORT=${PORT:-8000}

echo
echo "Launching the development server on http://$FLASK_RUN_HOST:$FLASK_RUN_PORT"
echo "Admin login -> Username: ${ADMIN_USERNAME:-admin} | Password: ${ADMIN_PASSWORD:-admin123}"
echo "Press CTRL+C to stop the server."

exec flask run
