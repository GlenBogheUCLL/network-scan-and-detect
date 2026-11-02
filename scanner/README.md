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

-------------------------
Technical Goals
-------------------------

This project is intentionally built without relying on full-featured security libraries in order to:

-Understand socket-level networking

-Implement detection logic from scratch

-Explore cross-platform behavior (Windows/Linux)

-Model attacker-to-defender workflow
