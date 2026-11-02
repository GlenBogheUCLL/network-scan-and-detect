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
retained with an empty vulnerability list.

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

-------------------------
Technical Goals
-------------------------

This project is intentionally built without relying on full-featured security libraries in order to:

-Understand socket-level networking

-Implement detection logic from scratch

-Explore cross-platform behavior (Windows/Linux)

-Model attacker-to-defender workflow
