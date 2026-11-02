from datetime import UTC, datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    target: Mapped[str] = mapped_column(String(255), index=True)
    internet_facing: Mapped[bool]
    overall_risk_score: Mapped[float] = mapped_column(Float)
    overall_severity: Mapped[str] = mapped_column(String(20))
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(UTC), nullable=False
    )
    ports: Mapped[list["PortResult"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class PortResult(Base):
    __tablename__ = "port_results"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(10))
    state: Mapped[str] = mapped_column(String(20))
    service: Mapped[str] = mapped_column(String(100))
    product: Mapped[str | None] = mapped_column(String(255))
    version: Mapped[str | None] = mapped_column(String(100))
    confidence: Mapped[float | None] = mapped_column(Float)
    risk_score: Mapped[float] = mapped_column(Float)
    risk_severity: Mapped[str] = mapped_column(String(20))
    highest_cvss: Mapped[float] = mapped_column(Float)
    vulnerability_count: Mapped[int] = mapped_column(Integer)
    risk_reasons: Mapped[str] = mapped_column(Text)
    scan: Mapped[Scan] = relationship(back_populates="ports")
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(
        back_populates="port_result", cascade="all, delete-orphan"
    )


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(primary_key=True)
    port_result_id: Mapped[int] = mapped_column(
        ForeignKey("port_results.id"), index=True
    )
    cve_id: Mapped[str] = mapped_column(String(30), index=True)
    description: Mapped[str] = mapped_column(Text)
    cvss_score: Mapped[float | None] = mapped_column(Float)
    severity: Mapped[str | None] = mapped_column(String(20))
    vector: Mapped[str | None] = mapped_column(String(255))
    port_result: Mapped[PortResult] = relationship(back_populates="vulnerabilities")
