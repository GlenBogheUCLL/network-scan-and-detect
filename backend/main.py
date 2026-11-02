import json
import socket
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, status
from sqlalchemy.orm import Session, selectinload
from sqlalchemy import select

from scanner.risk_engine import assess_scan

from .database import Base, create_database, session_dependency
from .models import PortResult, Scan, Vulnerability
from scanner.nvd_client import NvdClient
from .schemas import (
    PortResponse,
    ScanInput,
    ScanRequest,
    ScanResponse,
    VulnerabilityResponse,
)
from scanner.tcp_scan import scan_ports


def create_app(database_url=None):
    engine, session_factory = create_database(database_url)

    @asynccontextmanager
    async def lifespan(app):
        Base.metadata.create_all(engine)
        yield

    app = FastAPI(title="Network Scan and Detect API", lifespan=lifespan)

    def get_session():
        yield from session_dependency(session_factory)

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.post(
        "/scan",
        response_model=ScanResponse,
        status_code=status.HTTP_201_CREATED,
    )
    def run_scan(payload: ScanRequest, session: Session = Depends(get_session)):
        if payload.start_port > payload.end_port:
            raise HTTPException(
                status_code=422,
                detail="start_port must be less than or equal to end_port.",
            )
        try:
            socket.gethostbyname(payload.target)
            if payload.start_port < 1 or payload.end_port > 65535:
                raise ValueError("Port range must be between 1 and 65535.")
            scan_results = scan_ports(
                payload.target,
                payload.start_port,
                payload.end_port,
            )
            scan_data = {
                "target": payload.target,
                "results": [result.to_dict() for result in scan_results],
            }
            vulnerability_results = NvdClient().lookup_scan_results(scan_data)
            scan_data["results"] = vulnerability_results
            return _store_scan(
                session,
                scan_data,
                payload.internet_facing,
            )
        except (ValueError, KeyError) as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
        except RuntimeError as error:
            raise HTTPException(status_code=502, detail=str(error)) from error

    @app.post(
        "/scans",
        response_model=ScanResponse,
        status_code=status.HTTP_201_CREATED,
    )
    def create_scan(payload: ScanInput, session: Session = Depends(get_session)):
        try:
            return _store_scan(
                session,
                payload.model_dump(),
                payload.internet_facing,
            )
        except (ValueError, KeyError) as error:
            raise HTTPException(status_code=422, detail=str(error)) from error

    @app.get("/scans/{scan_id}", response_model=ScanResponse)
    def get_scan(scan_id: int, session: Session = Depends(get_session)):
        scan = _load_scan(session, scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail="Scan not found.")
        return _serialize_scan(session, scan.id)

    return app


def _store_scan(session, scan_data, internet_facing):
    risk_data = assess_scan(scan_data, internet_facing)
    scan = Scan(
        target=scan_data["target"],
        internet_facing=internet_facing,
        overall_risk_score=risk_data["overall_risk_score"],
        overall_severity=risk_data["overall_severity"],
    )
    assessments_by_port = {
        assessment["port"]: assessment for assessment in risk_data["results"]
    }
    for result in scan_data["results"]:
        if result["state"] != "open":
            continue
        assessment = assessments_by_port[result["port"]]
        port = PortResult(
            port=result["port"],
            protocol=result.get("protocol", "tcp"),
            state=result["state"],
            service=result.get("service", "unknown"),
            product=result.get("product"),
            version=result.get("version"),
            confidence=result.get("confidence"),
            risk_score=assessment["risk_score"],
            risk_severity=assessment["severity"],
            highest_cvss=assessment["highest_cvss"],
            vulnerability_count=assessment["vulnerability_count"],
            risk_reasons=json.dumps(assessment["reasons"]),
        )
        port.vulnerabilities = [
            Vulnerability(
                cve_id=vulnerability["cve_id"],
                description=vulnerability.get("description", ""),
                cvss_score=vulnerability.get("cvss_score"),
                severity=vulnerability.get("severity"),
                vector=vulnerability.get("vector"),
            )
            for vulnerability in result.get("vulnerabilities", [])
        ]
        scan.ports.append(port)
    session.add(scan)
    session.commit()
    return _serialize_scan(session, scan.id)


def _load_scan(session, scan_id):
    return session.scalar(
        select(Scan)
        .options(selectinload(Scan.ports).selectinload(PortResult.vulnerabilities))
        .where(Scan.id == scan_id)
    )


def _serialize_scan(session, scan_id):
    scan = _load_scan(session, scan_id)
    results = []
    for port in scan.ports:
        results.append(
            PortResponse(
                port=port.port,
                protocol=port.protocol,
                state=port.state,
                service=port.service,
                product=port.product,
                version=port.version,
                confidence=port.confidence,
                risk_score=port.risk_score,
                risk_severity=port.risk_severity,
                highest_cvss=port.highest_cvss,
                vulnerability_count=port.vulnerability_count,
                reasons=json.loads(port.risk_reasons),
                vulnerabilities=[
                    VulnerabilityResponse.model_validate(vulnerability)
                    for vulnerability in port.vulnerabilities
                ],
            )
        )
    return ScanResponse(
        id=scan.id,
        target=scan.target,
        internet_facing=scan.internet_facing,
        overall_risk_score=scan.overall_risk_score,
        overall_severity=scan.overall_severity,
        created_at=scan.created_at,
        results=results,
    )


app = create_app()
