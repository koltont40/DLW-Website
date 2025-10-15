# DLW Website

This project provides a self-hosted client onboarding, billing, and support portal built with Flask and SQLite. It includes:

- A marketing landing page with a call-to-action for prospective clients.
- A client signup form that captures contact details and project notes.
- A password-protected management dashboard for viewing, updating, and deleting client records.
- A secure customer portal where subscribers can review invoices, equipment, and open support tickets.

## Features

- **Client Signup** – Collect name, email, company, project type, and notes.
- **Dashboard Overview** – View key metrics (total clients, new this week, outstanding balance, open tickets) and filter the client table by status.
- **Client Management** – Update client status and notes, issue portal passwords, and curate navigation/branding assets.
- **Billing Operations** – Create, edit, and delete invoices with due dates and lifecycle statuses that sync to the customer portal.
- **Equipment Tracking** – Record installed hardware (model, serial, install date, notes) for each account.
- **Support Ticketing** – Monitor and update customer-submitted tickets with resolution notes from the admin dashboard.
- **Customer Portal** – Clients log in with a password to see balances, hardware details, appointments, and submit new support tickets.
- **Field Appointments** – Schedule installs or service calls, capture customer responses, and approve reschedules from the admin dashboard.
- **SNMP Notifications** – Stream appointment updates and on-demand emails to your operations tooling via configurable SNMP traps.
- **Service Plan Management** – Update residential, business, and phone offerings that power signup flows and public pricing pages.
- **Phone Service Landing** – Share hosted voice benefits and plan details on a dedicated page that links straight into signup and the customer portal.
- **Configurable Contact Details** – Set a single contact email that powers navigation links, portal reminders, and signup confirmations.
- **Blog Publishing** – Draft, publish, and manage updates from the admin dashboard that surface on the public blog.
- **One-Command Install** – Run `./install.sh` on Ubuntu 24.04 to provision dependencies, initialize the SQLite database, and start the development server (use `sudo` if you need permission to bind to ports 80/443).

## Quick Start (Ubuntu 24.04)

```bash
sudo apt update && sudo apt install -y python3 python3-venv python3-pip certbot
./install.sh
```

The script will create a Python virtual environment, install dependencies, initialize the database, and run the Flask development server on port 8000. Open <http://localhost:8000> in your browser.

### Pulling Future Updates

When new releases are published you can stay up to date without rerunning the installer. From inside the project directory, run:

```bash
./update.sh
```

The helper script verifies you have `git` available, fetches the latest commits for your current branch, rebases your local copy, and refreshes dependencies inside the existing virtual environment. If you have local changes you will be prompted to commit or stash them before continuing.

### Creating the First Administrator

Set the `ADMIN_USERNAME`, `ADMIN_PASSWORD`, and optional `ADMIN_EMAIL` environment variables before the first launch to auto-create your initial administrator. If those values are omitted the database will be initialized without an admin account—sign in via another trusted path (for example, `flask shell`) to create one manually before exposing the dashboard.

Each client can be issued a customer-portal password from the admin dashboard. Generate a temporary password or set a custom credential, then share it securely with the subscriber.

After signing in you can add or remove additional administrators from **Dashboard → Security** so multiple staff members can manage the portal.

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
    ├── document_viewer.html # Inline legal viewer
    ├── index.html      # Landing page
    ├── login.html      # Admin login form
    ├── about.html      # Company story
    ├── service_plans.html # Public service plans
    ├── blog.html       # Public blog listing
    ├── blog_post.html  # Individual blog article
    ├── portal_dashboard.html # Customer portal home
    ├── portal_login.html     # Customer login form
    └── signup.html     # Client signup form
```

## Environment Variables

| Variable | Purpose | Default |
| --- | --- | --- |
| `SECRET_KEY` | Flask session secret | Randomly generated if unset |
| `ADMIN_USERNAME` | Dashboard login username used to seed the first admin | unset (required to auto-create an admin) |
| `ADMIN_PASSWORD` | Dashboard login password used to seed the first admin | unset (required to auto-create an admin) |
| `ADMIN_EMAIL` | Optional email to assign to the seeded administrator | unset |
| `PORT` | Optional secondary HTTP port (in addition to port 80) | unset |
| `HTTPS_PORT` | Optional secondary HTTPS port (in addition to port 443) | unset |
| `CONTACT_EMAIL` | Primary support/contact email surfaced throughout the site | `info@dixielandwireless.com` |
| `CONTACT_PHONE` | Support phone number shown on public pages and navigation | `2053343969` |
| `STRIPE_SECRET_KEY` | Server-side API key for payment processing, autopay, and refunds | unset (Stripe disabled) |
| `STRIPE_PUBLISHABLE_KEY` | Publishable key used by Stripe.js in the client portal | unset |
| `STRIPE_WEBHOOK_SECRET` | Signing secret for validating Stripe webhooks | unset |
| `SNMP_TRAP_HOST` | Hostname/IP for SNMP trap delivery | unset (disabled) |
| `SNMP_TRAP_PORT` | UDP port for SNMP trap delivery | `162` |
| `SNMP_COMMUNITY` | SNMP community string | `public` |
| `SNMP_ENTERPRISE_OID` | Enterprise OID prefix for emitted traps | `1.3.6.1.4.1.8072.9999` |
| `SNMP_ADMIN_EMAIL` | Operations email to notify on client responses | unset |

### SNMP Email Notifications

When `SNMP_TRAP_HOST` is provided the application emits SNMP traps for appointment events (new bookings, customer reschedules, and approvals). Many network monitoring platforms can translate these traps into emails or tickets. Customize delivery with:

- `SNMP_TRAP_PORT`, `SNMP_COMMUNITY`, and `SNMP_ENTERPRISE_OID` to match your monitoring stack.
- `SNMP_ADMIN_EMAIL` so client responses trigger a notification to your operations inbox.

Administrators can also compose ad-hoc SNMP-backed emails from the Support section of the dashboard to broadcast outage updates or reminders.

During automated testing you can override the trap sender by assigning a callable to `app.config["SNMP_EMAIL_SENDER"]`.

### Stripe Payments & Autopay

Stripe powers secure card storage, customer-initiated payments, dashboard refunds, and automated autopay runs. Provide your Stripe credentials before launching production instances:

1. Create API keys from the Stripe dashboard and export `STRIPE_SECRET_KEY` and `STRIPE_PUBLISHABLE_KEY` in the environment where the app runs.
2. Configure a webhook endpoint that points to `/stripe/webhook` and assign its signing secret to `STRIPE_WEBHOOK_SECRET` so events are verified.
3. Ask customers to add cards or toggle autopay from the client portal. Administrators can still paste a Stripe payment method ID (for example `pm_123...`) if they create one from the Stripe dashboard.
4. When autopay runs the app confirms off-session charges through Stripe and records outcomes through the webhook. Successful manual payments and refunds also flow through the same webhook channel, keeping invoice statuses in sync automatically.

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

Automated tests cover the main user flows including landing page rendering, signup, authentication, legal document management, dashboard operations, billing/equipment CRUD, and the customer portal experience. Install the development dependencies and run `pytest`:

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
