# DLW Website

This project provides a self-hosted client onboarding and management portal built with Flask and SQLite. It includes:

- A marketing landing page with a call-to-action for prospective clients.
- A client signup form that captures contact details and project notes.
- A password-protected management dashboard for viewing, updating, and deleting client records.

## Features

- **Client Signup** – Collect name, email, company, project type, and notes.
- **Dashboard Overview** – View key metrics (total clients, new this week) and filter the client table by status.
- **Client Management** – Update client status and notes or remove records entirely.
- **One-Command Install** – Run `./install.sh` on Ubuntu 24.04 to provision dependencies, initialize the SQLite database, and start the development server.

## Quick Start (Ubuntu 24.04)

```bash
sudo apt update && sudo apt install -y python3 python3-venv python3-pip
./install.sh
```

The script will create a Python virtual environment, install dependencies, initialize the database, and run the Flask development server on port 8000. Open <http://localhost:8000> in your browser.

### Default Admin Credentials

- **Username:** `admin`
- **Password:** `admin123`

Change these by setting the `ADMIN_USERNAME` and `ADMIN_PASSWORD` environment variables before launching the app.

## Project Structure

```
.
├── app.py              # Flask application entry point
├── install.sh          # One-command installer and launcher
├── requirements.txt    # Python dependencies
├── README.md           # Project documentation
├── static/
│   └── styles.css      # Global styles
└── templates/
    ├── base.html       # Shared layout
    ├── dashboard.html  # Admin dashboard UI
    ├── index.html      # Landing page
    ├── login.html      # Admin login form
    └── signup.html     # Client signup form
```

## Environment Variables

| Variable | Purpose | Default |
| --- | --- | --- |
| `SECRET_KEY` | Flask session secret | Randomly generated if unset |
| `ADMIN_USERNAME` | Dashboard login username | `admin` |
| `ADMIN_PASSWORD` | Dashboard login password | `admin123` |
| `PORT` | Server port | `8000` |

## Development Notes

- The SQLite database file lives at `instance/clients.db`. It is created automatically if it does not exist.
- The app uses server-side sessions; keep the `SECRET_KEY` safe in production.
- To stop the server started by `install.sh`, press `Ctrl+C`.

## Running Manually

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m flask --app app run --debug
```

Before first run, initialize the database:

```bash
python -c "from app import init_db; init_db()"
```

## Testing the Application

Automated tests cover the main user flows (landing page, signup, authentication, and dashboard access). Install the development dependencies and run `pytest`:

```bash
pip install -r requirements-dev.txt
pytest
```

You can also test manually after launching the server:

1. Visit `/signup` and submit the form to create a client record.
2. Log into `/login` with the admin credentials to review the new client in the dashboard.
3. Update client status, edit notes, or delete the record from the dashboard.

## License

This project is provided as-is for demonstration purposes.
