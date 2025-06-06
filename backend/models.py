from pydantic import BaseModel
from datetime import datetime
from typing import List, Optional, Dict, Any

class ThreatDetection(BaseModel):
    type: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    count: int
    description: str

class LogAnalysisRequest(BaseModel):
    log_content: str

class AnalysisResponse(BaseModel):
    threats_detected: List[ThreatDetection]
    ai_analysis: str
    total_lines: int
    analysis_time: datetime
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL

class PatternAnalysisResponse(BaseModel):
    suspicious_ips: List[str]
    attack_timeline: str
    coordinated_attacks: str
    anomalies: List[str]
    geographic_concerns: str
    recommendations: List[str]
    analysis_time: datetime

class UploadResponse(BaseModel):
    message: str
    filename: str
    file_size: int

class ErrorResponse(BaseModel):
    error: str
    detail: str
    timestamp: datetime

class APIInfoResponse(BaseModel):
    service: str
    version: str
    ai_powered: bool
    threat_detection: Dict[str, Any]
    analysis_features: List[str]
    supported_formats: List[str]
    ai_model: str

# New models for enhanced features

class GeoIPInfo(BaseModel):
    ip: str
    country: str
    city: Optional[str]
    latitude: Optional[float]
    longitude: Optional[float]
    isp: Optional[str]
    is_threat: bool
    threat_type: Optional[str]
    threat_score: Optional[int]
    last_reported: Optional[datetime]

class EnrichedIP(BaseModel):
    ip: str
    geo_data: GeoIPInfo
    occurrences: int
    associated_events: List[str]

class MITREAttackTechnique(BaseModel):
    technique_id: str
    name: str
    description: str
    url: str
    severity: str
    confidence: float

class OWASPVulnerability(BaseModel):
    owasp_id: str
    name: str
    description: str
    url: str
    severity: str
    confidence: float

class FrameworkMapping(BaseModel):
    mitre_techniques: List[MITREAttackTechnique]
    owasp_vulnerabilities: List[OWASPVulnerability]

class TimelineEvent(BaseModel):
    timestamp: datetime
    event_type: str
    severity: str
    source_ip: Optional[str]
    target: Optional[str]
    description: str

class DashboardData(BaseModel):
    timeline_events: List[TimelineEvent]
    ip_frequency: Dict[str, int]
    attack_distribution: Dict[str, int]
    severity_counts: Dict[str, int]
    geographic_data: List[GeoIPInfo]

class ForensicReport(BaseModel):
    report_id: str
    generated_at: datetime
    executive_summary: str
    key_findings: List[str]
    threat_actors: List[Dict[str, Any]]
    indicators_of_compromise: List[Dict[str, Any]]
    attack_timeline: List[TimelineEvent]
    framework_mapping: FrameworkMapping
    affected_systems: List[str]
    recommendations: List[Dict[str, Any]]
    technical_details: Dict[str, Any]