from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class VulnerabilityInput(BaseModel):
    cve_id: str
    description: str = ""
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    severity: str | None = None
    vector: str | None = None


class PortInput(BaseModel):
    port: int = Field(ge=1, le=65535)
    protocol: str = "tcp"
    state: str
    service: str = "unknown"
    product: str | None = None
    version: str | None = None
    banner: str | None = None
    confidence: float | None = Field(default=None, ge=0, le=1)
    vulnerabilities: list[VulnerabilityInput] = Field(default_factory=list)


class ScanInput(BaseModel):
    target: str = Field(min_length=1, max_length=255)
    internet_facing: bool = False
    results: list[PortInput]


class ScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=255)
    start_port: int = Field(ge=1, le=65535)
    end_port: int = Field(ge=1, le=65535)
    internet_facing: bool = False


class VulnerabilityResponse(VulnerabilityInput):
    model_config = ConfigDict(from_attributes=True)


class PortResponse(BaseModel):
    port: int
    protocol: str
    state: str
    service: str
    product: str | None
    version: str | None
    confidence: float | None
    risk_score: float
    risk_severity: str
    highest_cvss: float
    vulnerability_count: int
    reasons: list[str]
    vulnerabilities: list[VulnerabilityResponse]


class ScanResponse(BaseModel):
    id: int
    target: str
    internet_facing: bool
    overall_risk_score: float
    overall_severity: str
    created_at: Any
    results: list[PortResponse]
