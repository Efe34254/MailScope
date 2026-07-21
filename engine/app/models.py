from __future__ import annotations
from typing import Any, Literal
from pydantic import BaseModel, Field

class Address(BaseModel):
    display_name: str = ""
    address: str = ""
    domain: str = ""

class SourceInfo(BaseModel):
    type: Literal["eml"] = "eml"
    file_name: str
    file_size: int
    sha256: str

class EmailContent(BaseModel):
    text_available: bool
    html_available: bool
    text_length: int
    html_length: int
    text_preview: str = ""
    html_preview: str = ""

class EmailData(BaseModel):
    subject: str = ""
    from_: Address = Field(default_factory=Address, alias="from")
    to: list[Address] = Field(default_factory=list)
    cc: list[Address] = Field(default_factory=list)
    reply_to: list[Address] = Field(default_factory=list)
    return_path: str = ""
    date: str = ""
    message_id: str = ""
    received: list[str] = Field(default_factory=list)
    content: EmailContent
    raw_headers: str = ""
    raw_source_preview: str = ""
    model_config = {"populate_by_name": True}

class IOC(BaseModel):
    ioc_id: str
    type: Literal["url", "domain", "ipv4", "ipv6", "email"]
    value: str
    normalized_value: str
    source: dict[str, str]
    classification: dict[str, Any]

class Attachment(BaseModel):
    attachment_id: str
    file_name: str
    sanitized_file_name: str
    declared_content_type: str
    detected_type: str = "unknown"
    size: int
    entropy: float = 0.0
    hashes: dict[str, str]
    stored_path: str
    static_flags: list[str] = Field(default_factory=list)
    analysis_status: Literal[
        "analyzed", "partially_analyzed", "encrypted", "unsupported",
        "timed_out", "tool_failed", "blocked_by_safety_limit",
    ] = "analyzed"
    parent_attachment_id: str = ""
    depth: int = 0
    is_embedded: bool = False
    extracted_from: str = ""
    extraction_notes: list[str] = Field(default_factory=list)

class Finding(BaseModel):
    finding_id: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    category: str
    title: str
    description: str
    evidence: str = ""
    tool_id: str
    risk_points: int | None = None

class ToolReport(BaseModel):
    tool_id: str
    name: str
    category: str
    status: Literal["clean", "info", "warning", "suspicious", "unavailable", "error"]
    summary: str
    metrics: dict[str, Any] = Field(default_factory=dict)
    details: list[str] = Field(default_factory=list)

class RiskAssessment(BaseModel):
    model_version: str = "3.0"
    score: int = 0
    level: Literal["informational", "low", "medium", "high", "critical"] = "informational"
    confidence: Literal["high", "medium", "low", "local-only"] = "high"
    coverage: Literal["high", "medium", "low", "local-only"] = "high"
    reasons: list[str] = Field(default_factory=list)
    score_breakdown: list[dict[str, Any]] = Field(default_factory=list)
    category_breakdown: list[dict[str, Any]] = Field(default_factory=list)
    incomplete_checks: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)

class AnalysisResult(BaseModel):
    schema_version: str = "3.0"
    analysis_id: str
    created_at: str
    status: Literal["completed", "failed", "partial"]
    source: SourceInfo
    email: EmailData
    iocs: list[IOC]
    attachments: list[Attachment]
    findings: list[Finding] = Field(default_factory=list)
    tool_reports: list[ToolReport] = Field(default_factory=list)
    risk: RiskAssessment = Field(default_factory=RiskAssessment)
    errors: list[str] = Field(default_factory=list)
