from django.db import models
from django.contrib.postgres.fields import ArrayField

from django.utils import timezone

# ============================================
# REPORTING SUMMARY MODEL
# ============================================
class ReportSummary(models.Model):
    """Domain/asset/scan scoped security summary export record"""
    organization_name = models.CharField(max_length=255)
    domain = models.ForeignKey('Domain', on_delete=models.CASCADE, related_name='report_summaries')
    asset = models.ForeignKey('Asset', on_delete=models.SET_NULL, related_name='report_summaries', null=True, blank=True)
    scan = models.ForeignKey('Scan', on_delete=models.SET_NULL, related_name='report_summaries', null=True, blank=True)
    generated_at = models.DateTimeField(default=timezone.now)
    executive_summary = models.TextField(blank=True)
    scope_note = models.CharField(max_length=500, blank=True)
    total_findings = models.IntegerField(default=0)
    critical_risk = models.IntegerField(default=0)
    high_risk = models.IntegerField(default=0)
    medium_risk = models.IntegerField(default=0)
    low_risk = models.IntegerField(default=0)

    class Meta:
        db_table = 'report_summary'
        ordering = ['-generated_at']

    def __str__(self):
        scope = self.asset.value if self.asset else self.domain.root_domain
        return f"{self.organization_name} - {scope}"


class ReportSummaryFinding(models.Model):
    """Concise summary finding with external reference link"""
    SEVERITY_CHOICES = [
        ('Critical', 'Critical'),
        ('High', 'High'),
        ('Medium', 'Medium'),
        ('Low', 'Low'),
    ]

    summary = models.ForeignKey(ReportSummary, on_delete=models.CASCADE, related_name='findings')
    finding_type = models.CharField(max_length=80)
    title = models.CharField(max_length=300)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    risk_summary = models.CharField(max_length=400)
    external_reference = models.URLField()
    affected_asset = models.CharField(max_length=500)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'report_summary_finding'
        ordering = ['created_at']

    def __str__(self):
        return f"{self.title} ({self.severity})"


# ============================================
# DOMAIN & ASSET MODELS
# ============================================

class Domain(models.Model):
    """Core domain model for managing monitored domains"""
    STATUS_CHOICES = [
        ('Active', 'Active'),
        ('Inactive', 'Inactive'),
        ('Suspended', 'Suspended'),
    ]
    
    root_domain = models.CharField(max_length=255, unique=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Active')
    registrar = models.CharField(max_length=255, blank=True, null=True)
    expiry_date = models.DateTimeField(blank=True, null=True)
    owner = models.CharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'domains'
        ordering = ['root_domain']
        indexes = [
            models.Index(fields=['status']),
            models.Index(fields=['expiry_date']),
        ]
    
    def __str__(self):
        return self.root_domain


class Asset(models.Model):
    """Assets discovered under domains (subdomains, URLs)"""
    ASSET_TYPE_CHOICES = [
        ('root_domain', 'Root Domain'),
        ('subdomain', 'Subdomain'),
        ('url', 'URL'),
    ]
    
    domain = models.ForeignKey(Domain, on_delete=models.CASCADE, related_name='assets')
    asset_type = models.CharField(max_length=20, choices=ASSET_TYPE_CHOICES)
    value = models.CharField(max_length=500)  # URL or domain value
    source = models.CharField(max_length=100)  # Discovery method
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    discovered_at = models.DateTimeField(auto_now_add=True)
    last_verified = models.DateTimeField(blank=True, null=True)
    
    class Meta:
        db_table = 'assets'
        ordering = ['-discovered_at']
        indexes = [
            models.Index(fields=['domain', 'asset_type']),
            models.Index(fields=['value']),
        ]
    
    def __str__(self):
        return f"{self.asset_type}: {self.value}"


# ============================================
# SCAN MODELS
# ============================================

class Scan(models.Model):
    """Main scan execution records"""
    SCAN_TYPE_CHOICES = [
        ('on-demand', 'On-Demand'),
        ('scheduled', 'Scheduled'),
        ('triggered', 'Triggered'),
    ]
    
    STATUS_CHOICES = [
        ('queued', 'Queued'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
    ]
    
    initiated_by = models.IntegerField(blank=True, null=True)  # User ID placeholder
    scan_type = models.CharField(max_length=20, choices=SCAN_TYPE_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='queued')
    started_at = models.DateTimeField(blank=True, null=True)
    finished_at = models.DateTimeField(blank=True, null=True)
    duration_seconds = models.IntegerField(blank=True, null=True)
    error_message = models.TextField(blank=True, null=True)
    cancel_requested = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'scans'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['status']),
            models.Index(fields=['scan_type']),
            models.Index(fields=['-created_at']),
        ]
    
    def __str__(self):
        return f"Scan {self.id} - {self.status}"


class ScanAsset(models.Model):
    """Junction table linking scans to assets"""
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='scan_assets')
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name='asset_scans')
    scan_started = models.DateTimeField(blank=True, null=True)
    scan_completed = models.DateTimeField(blank=True, null=True)
    
    class Meta:
        db_table = 'scan_assets'
        unique_together = ['scan', 'asset']
    
    def __str__(self):
        return f"Scan {self.scan_id} - Asset {self.asset_id}"


# ============================================
# FINDING MODELS
# ============================================

class Finding(models.Model):
    """Security findings from scans"""
    CATEGORY_CHOICES = [
        ('CVE', 'CVE'),
        ('SSL', 'SSL'),
        ('DNS', 'DNS'),
        ('Email', 'Email'),
        ('Misconfiguration', 'Misconfiguration'),
    ]
    
    RISK_RATING_CHOICES = [
        ('Low', 'Low'),
        ('Medium', 'Medium'),
        ('High', 'High'),
        ('Critical', 'Critical'),
    ]
    
    STATUS_CHOICES = [
        ('open', 'Open'),
        ('in_progress', 'In Progress'),
        ('resolved', 'Resolved'),
        ('false_positive', 'False Positive'),
    ]
    
    CONFIDENCE_CHOICES = [
        ('High', 'High'),
        ('Medium', 'Medium'),
        ('Low', 'Low'),
    ]
    
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name='findings')
    title = models.CharField(max_length=500)
    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES)
    nuclei_template_id = models.CharField(max_length=200)
    nuclei_severity = models.CharField(max_length=50)
    cvss_score = models.FloatField(blank=True, null=True)
    cvss_vector = models.CharField(max_length=200, blank=True, null=True)
    risk_rating = models.CharField(max_length=20, choices=RISK_RATING_CHOICES)
    scoring_confidence = models.CharField(max_length=20, choices=CONFIDENCE_CHOICES)
    evidence = models.TextField()
    recommendation = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='open')
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'findings'
        ordering = ['-cvss_score', '-first_seen']
        indexes = [
            models.Index(fields=['asset', 'category']),
            models.Index(fields=['risk_rating']),
            models.Index(fields=['status']),
            models.Index(fields=['-cvss_score']),
        ]
    
    def __str__(self):
        return f"{self.title} - {self.risk_rating}"


class ScanFinding(models.Model):
    """Junction table linking scans to findings"""
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='scan_findings')
    finding = models.ForeignKey(Finding, on_delete=models.CASCADE, related_name='finding_scans')
    detected_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'scan_findings'
        unique_together = ['scan', 'finding']
    
    def __str__(self):
        return f"Scan {self.scan_id} - Finding {self.finding_id}"


class CVE(models.Model):
    """CVE database"""
    cve_id = models.CharField(max_length=50, unique=True)  # e.g., CVE-2024-1234
    cvss_score = models.FloatField(blank=True, null=True)
    cvss_vector = models.CharField(max_length=200, blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    reference_url = models.URLField(blank=True, null=True)
    published_date = models.DateTimeField(blank=True, null=True)
    last_modified = models.DateTimeField(blank=True, null=True)
    
    class Meta:
        db_table = 'cves'
        ordering = ['-published_date']
        indexes = [
            models.Index(fields=['cve_id']),
            models.Index(fields=['-cvss_score']),
        ]
    
    def __str__(self):
        return self.cve_id


class FindingCVE(models.Model):
    """Links findings to CVEs"""
    RELEVANCE_CHOICES = [
        ('direct', 'Direct'),
        ('indirect', 'Indirect'),
        ('related', 'Related'),
    ]
    
    finding = models.ForeignKey(Finding, on_delete=models.CASCADE, related_name='finding_cves')
    cve = models.ForeignKey(CVE, on_delete=models.CASCADE, related_name='cve_findings')
    relevance = models.CharField(max_length=20, choices=RELEVANCE_CHOICES)
    
    class Meta:
        db_table = 'finding_cves'
        unique_together = ['finding', 'cve']
    
    def __str__(self):
        return f"{self.finding.title} - {self.cve.cve_id}"


# ============================================
# SPECIFIC CHECK RESULT MODELS
# ============================================

class FrontendLibraryCheck(models.Model):
    """Frontend library vulnerability checks"""
    VULNERABILITY_STATUS_CHOICES = [
        ('up-to-date', 'Up-to-date'),
        ('outdated', 'Outdated'),
        ('vulnerable', 'Vulnerable'),
        ('unknown', 'Unknown'),              # ADD
        ('check-failed', 'Check Failed'),    # ADD
    ]
    
    RISK_LEVEL_CHOICES = [
        ('Low', 'Low'),
        ('Medium', 'Medium'),
        ('High', 'High'),
        ('Critical', 'Critical'),
    ]
    
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='library_checks')
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name='library_checks')
    library_name = models.CharField(max_length=200)
    detected_version = models.CharField(max_length=100)
    latest_version = models.CharField(max_length=100)
    vulnerability_status = models.CharField(max_length=20, choices=VULNERABILITY_STATUS_CHOICES)
    risk_level = models.CharField(max_length=20, choices=RISK_LEVEL_CHOICES)
    source_urls = models.JSONField(default=list)
    recommendation = models.TextField(blank=True)
    checked_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'frontend_library_checks'
        ordering = ['-checked_at']
    
    def __str__(self):
        return f"{self.library_name} {self.detected_version}"


class SSLTLSCheck(models.Model):
    """SSL/TLS security checks"""
    CHECK_TYPE_CHOICES = [
        ('certificate', 'Certificate'),
        ('protocol', 'Protocol'),
        ('cipher', 'Cipher'),
        ('hsts', 'HSTS'),
    ]
    
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='ssl_checks')
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name='ssl_checks')
    check_type = models.CharField(max_length=50, choices=CHECK_TYPE_CHOICES)
    finding = models.TextField()
    example = models.TextField(blank=True)
    cvss_score = models.FloatField()
    risk_rating = models.CharField(max_length=20)
    recommendation = models.TextField(blank=True)
    checked_at = models.DateTimeField(auto_now_add=True)
    
    # Additional fields for certificate checks
    certificate_expiry = models.DateTimeField(blank=True, null=True)
    certificate_days_remaining = models.IntegerField(blank=True, null=True)
    protocols_supported = models.JSONField(default=list)
    weak_ciphers = models.JSONField(default=list)
    
    class Meta:
        db_table = 'ssl_tls_checks'
        ordering = ['-checked_at']
    
    def __str__(self):
        return f"{self.check_type} - {self.asset.value}"


class EmailSecurityCheck(models.Model):
    """Email security (SPF, DKIM, DMARC) checks"""
    CHECK_TYPE_CHOICES = [
        ('SPF', 'SPF'),
        ('DKIM', 'DKIM'),
        ('DMARC', 'DMARC'),
    ]
    
    STATUS_CHOICES = [
        ('PASS', 'Pass'),
        ('FAIL', 'Fail'),
        ('INVALID', 'Invalid'),
    ]
    
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='email_checks')
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name='email_checks')
    check_type = models.CharField(max_length=20, choices=CHECK_TYPE_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES)
    details = models.TextField(blank=True)
    cvss_score = models.FloatField()
    risk_rating = models.CharField(max_length=20)
    recommendation = models.TextField(blank=True)
    record_value = models.TextField(blank=True)
    checked_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'email_security_checks'
        ordering = ['-checked_at']
    
    def __str__(self):
        return f"{self.check_type} - {self.status}"


class SecurityHeaderCheck(models.Model):
    """Security headers checks"""
    STATUS_CHOICES = [
        ('missing', 'Missing'),
        ('present', 'Present'),
        ('misconfigured', 'Misconfigured'),
    ]
    
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='header_checks')
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name='header_checks')
    header = models.CharField(max_length=200)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES)
    cvss_score = models.FloatField(blank=True, null=True)
    risk_rating = models.CharField(max_length=20)
    recommendation = models.TextField()
    header_value = models.TextField(blank=True)
    checked_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'security_header_checks'
        ordering = ['-checked_at']
    
    def __str__(self):
        return f"{self.header} - {self.status}"


class DNSSecurityCheck(models.Model):
    """DNS security checks"""
    CHECK_TYPE_CHOICES = [
        ('zone_transfer', 'Zone Transfer'),
        ('dnssec', 'DNSSEC'),
        ('hijacking', 'DNS Hijacking'),
        ('subdomain_takeover', 'Subdomain Takeover'),
    ]
    
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='dns_checks')
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name='dns_checks')
    check_type = models.CharField(max_length=50, choices=CHECK_TYPE_CHOICES)
    finding = models.TextField()
    example = models.TextField(blank=True)
    cvss_score = models.FloatField()
    risk_rating = models.CharField(max_length=20)
    recommendation = models.TextField(blank=True)
    checked_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'dns_security_checks'
        ordering = ['-checked_at']
    
    def __str__(self):
        return f"{self.check_type} - {self.asset.value}"

class TechnologyCheck(models.Model):
    scan = models.ForeignKey(Scan, related_name='technology_checks', on_delete=models.CASCADE)
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE)

    technology_name = models.CharField(max_length=200)
    version = models.CharField(max_length=100, default='Unknown', blank=True, null=True)
    latest_version = models.CharField(max_length=100, default='Unknown', blank=True, null=True)
    category = models.CharField(max_length=100, default='general')

    risk_level = models.CharField(
        max_length=20,
        choices=[('Low','Low'),('Medium','Medium'),('High','High')],
        default='Low'
    )

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.technology_name} {self.version}"