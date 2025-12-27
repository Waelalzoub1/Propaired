# Propaired (The Helper)

Propaired ("The Helper") is a **FastAPI** web app for connecting **customers** with **helpers** for short jobs/gigs.  
It includes authentication, profiles, job posting, in-app chat, and optional integrations for email verification and payments/background checks.

This repository is organized as a small monorepo with:
- **Server/**: the FastAPI app (pages + JSON endpoints)
- **Database/**: SQLite-backed persistence + search helpers
- **Customer/** and **Helper/**: HTML templates for each user type

---

## Features

- Customer + Helper login flows
- Helper profiles and availability/status
- Customer job posting / request workflow
- In-app chat, with **basic contact-sharing prevention** (email/phone/address pattern blocking in server code)
- Email verification + password reset flows
- Helper image upload/serving endpoint
- Location utilities (reverse geocode + location suggestion endpoints)
- Optional integrations:
  - **Stripe** webhooks / payments (configured via env)
  - **Checkr** webhook (configured via env)

---

## Tech Stack

- **Python**
- **FastAPI** (web server + APIs)
- **Jinja2** templates (server-rendered pages)
- **SQLite** (local database)
- Session signing via **itsdangerous**
- Pydantic models for request/response validation

---

## Repository Layout

```
Propaired/
├─ Server/                  # FastAPI app, routes, auth/session, email verification, webhooks
│  ├─ main.py               # Primary app: all pages + API endpoints
│  ├─ start_server.py       # Launch helper (TLS cert discovery + env setup)
│  └─ config/               # Local config files (DO NOT COMMIT REAL SECRETS)
├─ Database/                # SQLite DB helpers + search utilities
├─ Customer/templates/      # Customer-facing HTML templates
├─ Helper/templates/        # Helper-facing HTML templates
├─ dict/                    # Local dictionary data (used for search/synonyms)
└─ start_server.sh          # Convenience start script
```

---

## Quick Start (Local)

### 1) Create a virtual environment
```bash
python -m venv .venv
source .venv/bin/activate  # macOS/Linux
# .venv\Scripts\activate # Windows (PowerShell)
```

### 2) Install dependencies
```bash
pip install -r requirements.txt
```

### 3) Run the server
From the project root:
```bash
python Server/start_server.py
```

If you prefer the shell script (Linux/macOS):
```bash
chmod +x start_server.sh
./start_server.sh
```

Then open:
- http://127.0.0.1:8000

> Port may vary if you changed the launch configuration.

---

## Configuration

Configuration lives under `Server/config/`.

### Session secret (required)
The server expects a session secret file:
- `Server/config/HELPER_SESSION_SECRET`

**Important:** rotate this secret if it was ever committed publicly.

### SMTP email (optional but recommended)
`Server/config/smtp.env` contains SMTP settings used for verification/reset emails.

**Security note:** do not commit real SMTP passwords. Use app passwords and rotate immediately if exposed.

### Integrations (optional)
`Server/config/integrations.env` contains placeholders for:
- Stripe keys + webhook secret
- Checkr API key + webhook secret
- Fee/tax configuration
- Base URL for redirects/webhooks

If you leave integrations blank, the app should still run, but payment/background-check features may be disabled.

---

## Database

The app uses SQLite via Python's built-in `sqlite3`.  
The database file is stored in the `Database/` module directory (see `Database/database.py`).

For production, you will likely want to migrate to Postgres and add proper migrations.

---

## Development Notes

- Templates are split by user role:
  - `Customer/templates/`
  - `Helper/templates/`
- Most routes live in `Server/main.py`.
- Contact-sharing prevention is implemented via regex/pattern checks in server code. Treat this as **best-effort** (not a guarantee).

---

## Recommended Next Improvements

- Add `.env.example` files for `smtp.env` and `integrations.env` and ensure secrets are not committed
- Add formatting/linting (e.g., `ruff` + `black`)
- Add tests for core flows (auth/session, database helpers) using `pytest`
- Add Docker support for consistent local setup (optional)
- Add screenshots/GIFs of key flows (customer request, helper profile, chat)

---

## License

MIT License
