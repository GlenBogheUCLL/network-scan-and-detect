import json
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, status
from sqlalchemy.orm import Session, selectinload
from sqlalchemy import select

from scanner.risk_engine import assess_scan

from .database import Base, create_database, session_dependency
from .models import PortResult, Scan, Vulnerability
from .schemas import PortResponse, ScanInput, ScanResponse, VulnerabilityResponse


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
        "/scans",
        response_model=ScanResponse,
        status_code=status.HTTP_201_CREATED,
    )
    def create_scan(payload: ScanInput, session: Session = Depends(get_session)):
        scan_data = payload.model_dump()
        try:
            risk_data = assess_scan(scan_data, payload.internet_facing)
        except (ValueError, KeyError) as error:
            raise HTTPException(status_code=422, detail=str(error)) from error

        scan = Scan(
            target=payload.target,
            internet_facing=payload.internet_facing,
            overall_risk_score=risk_data["overall_risk_score"],
            overall_severity=risk_data["overall_severity"],
        )
        assessments_by_port = {
            assessment["port"]: assessment for assessment in risk_data["results"]
        }
        for port_input in payload.results:
            if port_input.state != "open":
                continue
            assessment = assessments_by_port[port_input.port]
            port = PortResult(
                port=port_input.port,
                protocol=port_input.protocol,
                state=port_input.state,
                service=port_input.service,
                product=port_input.product,
                version=port_input.version,
                confidence=port_input.confidence,
                risk_score=assessment["risk_score"],
                risk_severity=assessment["severity"],
                highest_cvss=assessment["highest_cvss"],
                vulnerability_count=assessment["vulnerability_count"],
                risk_reasons=json.dumps(assessment["reasons"]),
            )
            port.vulnerabilities = [
                Vulnerability(**vulnerability.model_dump())
                for vulnerability in port_input.vulnerabilities
            ]
            scan.ports.append(port)

        session.add(scan)
        session.commit()
        return _serialize_scan(session, scan.id)

    @app.get("/scans/{scan_id}", response_model=ScanResponse)
    def get_scan(scan_id: int, session: Session = Depends(get_session)):
        scan = _load_scan(session, scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail="Scan not found.")
        return _serialize_scan(session, scan.id)

    return app


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
