# SecuVanta

SecuVanta is a context-aware security intelligence and automated protection system for analyzing uploaded projects, identifying security findings, tracking security posture over time, and applying controlled protection policies.

## Features

- Project ZIP upload and isolated scanning
- Security finding detection and risk scoring
- Dependency vulnerability scanning using OSV vulnerability data
- Dependency scan status reporting and remediation guidance
- Security posture and risk trend analysis
- Finding lifecycle tracking
- Scan history and project-scoped history
- Monitor, Guarded, and Auto Protect modes
- Automatic protection for qualifying high-confidence findings

## ZIP Security Validation

Uploaded ZIP projects are validated before extraction.

- Duplicate-entry detection
- Normalized path collision detection
- Path traversal protection
- Absolute-path rejection
- Symlink rejection
- File-count limits
- Single-file size limits
- Total extracted-size limits
- Corrupted ZIP rejection

## Storage

SecuVanta uses project-scoped scan history.

When `DATABASE_URL` is configured, history is stored in PostgreSQL.

When `DATABASE_URL` is not configured, local development uses:

`data/scan_history.json`

## Local PostgreSQL / Neon Setup

For local development, SecuVanta can use a PostgreSQL database such as Neon.

Set the `DATABASE_URL` environment variable to the PostgreSQL connection string before starting the server.

PowerShell:

```powershell
$env:DATABASE_URL = "your-postgresql-connection-string"
python server/app.py
```

## Dependencies

The production database driver is:

`psycopg[binary]>=3.2,<4`

Dependencies are declared in `requirements.txt`. Install them with:

```powershell
python -m pip install -r requirements.txt
```

## Running Locally

Start the SecuVanta server from the project root:

```powershell
python server/app.py
```

The server uses port `8000` by default.

Open:

`http://localhost:8000/`

## Project Structure

```text
secuvanta/
|-- core/              # Security scanning, history, analytics, lifecycle and protection logic
|-- data/              # Local runtime data
|-- demo_project/      # Demonstration project
|-- server/            # HTTP server and API
|-- tests/             # Automated tests
|-- web/               # Frontend
|-- README.md
|-- requirements.txt
|-- STDLIB.md
|-- sentinelzero.py
`-- test_*.py           # Validation tests
```