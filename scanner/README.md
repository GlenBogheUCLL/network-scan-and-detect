# network-scan-and-detect
!!! WORK IN PROGRESS !!!
This project is actively being developed as part of my learning journey in networking and cybersecurity. Core functionality is being implemented incrementally, with additional detection logic and scanning capabilities planned.

----------------------------------
Project Overview
----------------------------------

Network Scan and Detect is designed to model both sides of security:

-Offensive reconnaissance — identifying exposed services on a network

-Defensive detection — analyzing logs to identify suspicious behavior

The goal of this project is to understand how exposed services lead to security events, and how those events can be detected using rule-based logic similar to a lightweight SIEM system.

This project focuses on practical implementation of:

-TCP/IP networking fundamentals

-Service fingerprinting

-Log normalization

-Brute-force detection logic

-Risk-based alert scoring

-Architecture Overview

Scanner → Exposed Services → Log Generation → Detection Engine → Alerts

The Network Scanner identifies open ports and running services.

Services generate authentication and access logs.

The Detection Engine analyzes logs for suspicious patterns.

Alerts are generated based on defined behavioral rules.

Usage
-----

Scan a target for open TCP ports and basic service information:

```powershell
python scanner/tcp_scan.py 127.0.0.1 1 1024
```

Save structured results for later use by the risk engine or dashboard:

```powershell
python scanner/tcp_scan.py 127.0.0.1 1 1024 --output scan-results.json
```

The JSON results include the port, protocol, state, detected service, optional
product and version, the fingerprint confidence, and the received banner.

The scanner includes protocol-specific fingerprints for HTTP, SSH, SMB/RPC and
VMware Authentication Daemon. A confidence value indicates how strongly the
service and product were identified; it does not represent exploitability.

Look up CVEs for results with a detected product and version:

```powershell
python scanner/nvd_client.py scan-results.json --output vulnerability-results.json
```

The NVD client uses the public NVD API. It first resolves an exact CPE 2.3
identifier for the detected product and version, then queries CVEs using that
exact CPE. Set `NVD_API_KEY` before running if you have an API key. Results
without a detected product and version, or without an exact CPE match, are
retained with an empty vulnerability list. Known ambiguous product names use
explicit vendor/product mappings and are never treated as an exact match
unless the CPE vendor, product and version all match.

Calculate transparent risk scores from the vulnerability results:

```powershell
python scanner/risk_engine.py vulnerability-results.json --output risk-results.json
```

Add the internet-facing penalty when the scanned machine is exposed to the
internet:

```powershell
python scanner/risk_engine.py vulnerability-results.json --internet-facing
```

Risk scoring starts with the highest CVSS score per open service. It adds
explicit penalties for incomplete fingerprints, unknown services, exposed FTP,
Telnet, rlogin or Redis, and optional internet exposure. Scores are capped at
10, and the overall score is the highest service score rather than an average.

Backend
-------

The project includes a FastAPI backend with PostgreSQL configuration. Install
the dependencies, set `DATABASE_URL`, and start the API from the repository
root:

```powershell
pip install -r requirements.txt
$env:DATABASE_URL = "postgresql+psycopg://scanner:scanner@localhost:5432/network_scan"
uvicorn backend.main:app --reload
```

Submit vulnerability results to `POST /scans`. The API stores scans, ports,
vulnerabilities, and risk assessments, and exposes saved scans through
`GET /scans/{scan_id}`. Interactive API documentation is available at
`http://127.0.0.1:8000/docs`.

The complete local stack also includes the API and a provisioned Grafana
dashboard:

```powershell
docker compose up -d --build
Invoke-WebRequest -Method Post -Uri http://127.0.0.1:8000/scans `
  -ContentType "application/json" -InFile vulnerability-results.json
```

Open `http://127.0.0.1:3000/d/network-scan-overview` to view the dashboard.
The default dashboard shows the latest overall score, severity distribution,
service risks, and CVEs.

PostgreSQL and Grafana
----------------------

Copy `.env.example` to `.env` and replace the example passwords. Start the
database and Grafana with:

```powershell
docker compose up -d
```

PostgreSQL is available on `localhost:5432` and Grafana on
`http://127.0.0.1:3000`. Grafana provisions the PostgreSQL datasource
automatically. Stop the services with `docker compose down`; add `-v` only
when you intentionally want to delete the stored database and dashboard data.
If port 5432 is already used locally, set `POSTGRES_PORT=5433` before starting;
the database remains available to the other containers at `postgres:5432`.

-------------------------
Technical Goals
-------------------------

This project is intentionally built without relying on full-featured security libraries in order to:

-Understand socket-level networking

-Implement detection logic from scratch

-Explore cross-platform behavior (Windows/Linux)

-Model attacker-to-defender workflow
