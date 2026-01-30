from django.db import models

class TestModel(models.Model):
    title = models.CharField(max_length=200)
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    
    def __str__(self):
        return self.title


# models.py

from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum
from pydantic import BaseModel, Field


# ============ ENUMS ============

class AssetType(str, Enum):
    ROOT_DOMAIN = "root_domain"
    SUBDOMAIN = "subdomain"
    URL = "url"


class ScanType(str, Enum):
    ON_DEMAND = "on-demand"
    SCHEDULED = "scheduled"
    TRIGGERED = "triggered"


class ScanStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class FindingStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class RiskRating(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class FindingCategory(str, Enum):
    CVE = "CVE"
    SSL = "SSL"
    DNS = "DNS"
    EMAIL = "Email"
    MISCONFIGURATION = "Misconfiguration"


class DomainStatus(str, Enum):
    ACTIVE = "Active"
    INACTIVE = "Inactive"
    SUSPENDED = "Suspended"


class ConfidenceLevel(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


# ============ CORE MODELS ============

class DomainBase(BaseModel):
    root_domain: str = Field(..., description="Root domain name")
    status: DomainStatus = Field(default=DomainStatus.ACTIVE)
    registrar: Optional[str] = None
    expiry_date: Optional[datetime] = None
    owner: Optional[str] = None


class DomainCreate(DomainBase):
    pass


class Domain(DomainBase):
    id: int
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class AssetBase(BaseModel):
    domain_id: int
    asset_type: AssetType
    value: str = Field(..., description="Asset URL or domain")
    source: str = Field(..., description="Discovery method")
    ip_address: Optional[str] = None


class AssetCreate(AssetBase):
    pass


class Asset(AssetBase):
    id: int
    discovered_at: datetime
    last_verified: Optional[datetime] = None
    
    class Config:
        from_attributes = True


class ScanBase(BaseModel):
    initiated_by: Optional[int] = None  # User ID placeholder
    scan_type: ScanType
    status: ScanStatus = Field(default=ScanStatus.QUEUED)
    error_message: Optional[str] = None


class ScanCreate(ScanBase):
    pass


class Scan(ScanBase):
    id: int
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    duration_seconds: Optional[int] = None
    created_at: datetime
    
    class Config:
        from_attributes = True


class ScanAssetBase(BaseModel):
    scan_id: int
    asset_id: int
    scan_started: Optional[datetime] = None
    scan_completed: Optional[datetime] = None


class ScanAssetCreate(ScanAssetBase):
    pass


class ScanAsset(ScanAssetBase):
    id: int
    
    class Config:
        from_attributes = True


class FindingBase(BaseModel):
    asset_id: int
    title: str
    category: FindingCategory
    nuclei_template_id: str
    nuclei_severity: str
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    risk_rating: RiskRating
    scoring_confidence: ConfidenceLevel
    evidence: str
    recommendation: str
    status: FindingStatus = Field(default=FindingStatus.OPEN)


class FindingCreate(FindingBase):
    pass


class Finding(FindingBase):
    id: int
    first_seen: datetime
    last_seen: datetime
    
    class Config:
        from_attributes = True


class ScanFindingBase(BaseModel):
    scan_id: int
    finding_id: int
    detected_at: datetime


class ScanFindingCreate(ScanFindingBase):
    pass


class ScanFinding(ScanFindingBase):
    id: int
    
    class Config:
        from_attributes = True


class CVEBase(BaseModel):
    cve_id: str = Field(..., pattern=r'^CVE-\d{4}-\d{4,}$')
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    description: Optional[str] = None
    reference_url: Optional[str] = None
    published_date: Optional[datetime] = None
    last_modified: Optional[datetime] = None


class CVECreate(CVEBase):
    pass


class CVE(CVEBase):
    id: int
    
    class Config:
        from_attributes = True


class FindingCVEBase(BaseModel):
    finding_id: int
    cve_id: int
    relevance: str = Field(..., description="direct/indirect/related")


class FindingCVECreate(FindingCVEBase):
    pass


class FindingCVE(FindingCVEBase):
    id: int
    
    class Config:
        from_attributes = True


# ============ SCANNING MODELS ============

class ScanRequest(BaseModel):
    domain_ids: List[int] = Field(..., description="List of domain IDs to scan")
    scan_type: ScanType = Field(default=ScanType.ON_DEMAND)
    template_categories: Optional[List[str]] = Field(
        default=None, 
        description="Specific template categories to run"
    )


class NucleiResult(BaseModel):
    template_id: str
    template_name: str
    severity: str
    host: str
    matched_at: str
    evidence: Optional[str] = None
    extracted_results: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None
    cvss_score: Optional[float] = None
    cve_ids: Optional[List[str]] = None


class ScanResult(BaseModel):
    scan_id: int
    asset_id: int
    findings: List[NucleiResult]
    scan_duration: float
    success: bool
    error_message: Optional[str] = None


# ============ SECURITY CHECK MODELS ============

class SecurityHeaderFinding(BaseModel):
    header: str
    status: str  # "missing" or "present"
    cvss_score: float
    risk_rating: RiskRating
    recommendation: str


class EmailSecurityFinding(BaseModel):
    check_type: str  # "SPF", "DKIM", "DMARC"
    status: str  # "PASS", "FAIL", "INVALID"
    details: Optional[str] = None
    cvss_score: float
    risk_rating: RiskRating


class SSLSecurityFinding(BaseModel):
    check_type: str  # "certificate", "protocol", "cipher", "hsts"
    finding: str
    example: Optional[str] = None
    cvss_score: float
    risk_rating: RiskRating


class FrontendLibraryFinding(BaseModel):
    library_name: str
    detected_version: str
    latest_version: str
    vulnerability_status: str  # "up-to-date", "outdated", "vulnerable"
    risk_level: RiskRating
    source_urls: List[str]


class DNSSecurityFinding(BaseModel):
    check_type: str  # "zone_transfer", "dnssec", "hijacking", "subdomain_takeover"
    finding: str
    example: Optional[str] = None
    cvss_score: float
    risk_rating: RiskRating


# ============ REPORTING MODELS ============

class ReportRequest(BaseModel):
    domain_ids: List[int]
    report_format: str = Field("pdf", pattern="^(pdf|doc|docx)$")
    include_history: bool = Field(default=True)
    custom_branding: Optional[Dict[str, Any]] = None


class ReportSection(BaseModel):
    title: str
    content: str
    order: int


class GeneratedReport(BaseModel):
    report_id: str
    domain_ids: List[int]
    report_format: str
    generated_at: datetime
    download_url: Optional[str] = None
    sections: List[ReportSection]


# ============ ALERTING MODELS ============

class AlertThreshold(BaseModel):
    cvss_min: float
    cvss_max: float
    delivery_method: str
    escalation_path: str


class Alert(BaseModel):
    alert_id: str
    finding_id: int
    severity: RiskRating
    alert_type: str
    message: str
    created_at: datetime
    acknowledged: bool = False
    acknowledged_at: Optional[datetime] = None
    delivery_channels: List[str]


# ============ DASHBOARD MODELS ============

class DashboardMetrics(BaseModel):
    total_domains: int
    active_vulnerabilities: int
    high_risk_cves: int
    scan_success_rate: float
    vulnerability_distribution: Dict[RiskRating, int]
    remediation_progress: Dict[str, int]


class TrendDataPoint(BaseModel):
    timestamp: datetime
    value: int
    category: str


class TrendAnalysis(BaseModel):
    metric_name: str
    data_points: List[TrendDataPoint]
    trend_direction: str  # "improving", "worsening", "stable"


# ============ COMPARISON MODELS ============

class ScanComparison(BaseModel):
    scan_a_id: int
    scan_b_id: int
    new_findings: List[Finding]
    resolved_findings: List[Finding]
    persistent_findings: List[Finding]
    comparison_date: datetime


class DomainComparison(BaseModel):
    domain_a_id: int
    domain_b_id: int
    common_findings: List[Finding]
    unique_to_a: List[Finding]
    unique_to_b: List[Finding]


# ============ BULK OPERATION MODELS ============

class BulkDomainUpload(BaseModel):
    domains: List[str]
    registrar: Optional[str] = None
    owner: Optional[str] = None
    validate_dns: bool = Field(default=True)


class BulkDomainResult(BaseModel):
    domain: str
    success: bool
    domain_id: Optional[int] = None
    error_message: Optional[str] = None


class BulkScanRequest(BaseModel):
    domain_ids: List[int]
    scan_type: ScanType = Field(default=ScanType.ON_DEMAND)
    priority: int = Field(default=1, ge=1, le=10)


# ============ TEMPLATE MANAGEMENT ============

class NucleiTemplate(BaseModel):
    id: str
    name: str
    category: str
    severity: str
    description: Optional[str] = None
    cve_ids: Optional[List[str]] = None
    cvss_score: Optional[float] = None
    tags: List[str] = []
    author: Optional[str] = None
    version: str = "1.0"
    false_positive_rate: Optional[float] = None
    last_updated: datetime


class TemplateUpdateRequest(BaseModel):
    template_ids: List[str]
    update_source: str = Field(..., description="cve_daily/security_weekly/config_monthly")
    force_update: bool = False


# ============ RESPONSE MODELS ============

class ApiResponse(BaseModel):
    success: bool
    message: str
    data: Optional[Any] = None
    error_code: Optional[str] = None


class PaginatedResponse(BaseModel):
    items: List[Any]
    total: int
    page: int
    page_size: int
    total_pages: int