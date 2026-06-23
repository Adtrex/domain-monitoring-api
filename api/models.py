import secrets
from datetime import timedelta

from django.db import models
from django.conf import settings
from django.contrib.postgres.fields import ArrayField

from django.utils import timezone
from django.utils.text import slugify


# ============================================
# ORGANISATION / TENANCY MODELS
# ============================================

def _default_invite_token():
    """Generate a URL-safe unique token for invitations."""
    return secrets.token_urlsafe(32)


def _default_invite_expiry():
    """Invitations are valid for 7 days by default."""
    return timezone.now() + timedelta(days=7)


class Organisation(models.Model):
    """Top-level tenant. Every piece of scan data is scoped to one organisation."""
    name = models.CharField(max_length=255, unique=True)
    slug = models.SlugField(max_length=255, unique=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'organisations'
        ordering = ['name']

    def save(self, *args, **kwargs):
        if not self.slug:
            base = slugify(self.name) or 'org'
            slug = base
            counter = 1
            while Organisation.objects.filter(slug=slug).exclude(pk=self.pk).exists():
                counter += 1
                slug = f"{base}-{counter}"
            self.slug = slug
        super().save(*args, **kwargs)

    def __str__(self):
        return self.name


class Membership(models.Model):
    """Links a Django user to exactly one organisation, with a role."""
    ROLE_CHOICES = [
        ('owner', 'Owner'),
        ('admin', 'Admin'),
        ('member', 'Member'),
    ]

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='membership',
    )
    organisation = models.ForeignKey(
        Organisation, on_delete=models.CASCADE, related_name='memberships'
    )
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='member')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'memberships'
        ordering = ['organisation', 'role', 'user_id']

    @property
    def can_manage_members(self):
        return self.role in ('owner', 'admin')

    def __str__(self):
        return f"{self.user} @ {self.organisation} ({self.role})"


class PlatformAdmin(models.Model):
    """A platform-wide super administrator.

    Decoupled from Django's is_superuser flag: presence of a row here grants
    full cross-organisation access *through the application/API*, without
    necessarily granting raw Django-admin/database access.
    """
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='platform_admin'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    note = models.CharField(max_length=255, blank=True)

    class Meta:
        db_table = 'platform_admins'

    def __str__(self):
        return f"PlatformAdmin: {self.user}"


class AuditLog(models.Model):
    """Append-only record of notable actions across the platform."""
    organisation = models.ForeignKey(
        Organisation, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='audit_logs',
    )
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='audit_actions',
    )
    actor_email = models.CharField(max_length=255, blank=True)
    action = models.CharField(max_length=80)
    target = models.CharField(max_length=300, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'audit_logs'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['-created_at']),
            models.Index(fields=['action']),
            models.Index(fields=['organisation', '-created_at']),
        ]

    def __str__(self):
        return f"{self.action} by {self.actor_email or 'system'} @ {self.created_at:%Y-%m-%d %H:%M}"


class Invitation(models.Model):
    """An email invite for a user to join an organisation and set their password."""
    ROLE_CHOICES = Membership.ROLE_CHOICES

    organisation = models.ForeignKey(
        Organisation, on_delete=models.CASCADE, related_name='invitations'
    )
    email = models.EmailField()
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='member')
    token = models.CharField(max_length=64, unique=True, default=_default_invite_token)
    invited_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
        null=True, blank=True, related_name='sent_invitations',
    )
    accepted = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(default=_default_invite_expiry)

    class Meta:
        db_table = 'invitations'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['token']),
            models.Index(fields=['email']),
        ]

    @property
    def is_expired(self):
        return timezone.now() > self.expires_at

    @property
    def is_valid(self):
        return not self.accepted and not self.is_expired

    def __str__(self):
        return f"Invite {self.email} -> {self.organisation} ({self.role})"


# ============================================
# REPORTING SUMMARY MODEL
# ============================================
class ReportSummary(models.Model):
    """Domain/asset/scan scoped security summary export record"""
    organisation = models.ForeignKey(
        Organisation, on_delete=models.CASCADE, related_name='report_summaries'
    )
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

    def save(self, *args, **kwargs):
        # Inherit organisation from the parent domain when not set explicitly.
        if self.organisation_id is None and self.domain_id is not None:
            self.organisation_id = self.domain.organisation_id
        super().save(*args, **kwargs)

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
    # TextField: stores free-form finding evidence which can exceed varchar(400).
    risk_summary = models.TextField(blank=True, default='')
    # TextField (not URLField): the report can join multiple long reference URLs
    # / Google-search fallback links that exceed the old varchar(200) limit.
    external_reference = models.TextField(blank=True, default='')
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
    
    organisation = models.ForeignKey(
        Organisation, on_delete=models.CASCADE, related_name='domains'
    )
    root_domain = models.CharField(max_length=255)
    # Each organisation has one primary domain, assigned by a platform admin.
    is_primary = models.BooleanField(default=False)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Active')
    registrar = models.CharField(max_length=255, blank=True, null=True)
    expiry_date = models.DateTimeField(blank=True, null=True)
    owner = models.CharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'domains'
        ordering = ['root_domain']
        unique_together = [('organisation', 'root_domain')]
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
    
    organisation = models.ForeignKey(
        Organisation, on_delete=models.CASCADE, related_name='assets'
    )
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

    def save(self, *args, **kwargs):
        # Inherit organisation from the parent domain when not set explicitly.
        if self.organisation_id is None and self.domain_id is not None:
            self.organisation_id = self.domain.organisation_id
        super().save(*args, **kwargs)

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
    
    organisation = models.ForeignKey(
        Organisation, on_delete=models.CASCADE, related_name='scans'
    )
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
    
    organisation = models.ForeignKey(
        Organisation, on_delete=models.CASCADE, related_name='findings'
    )
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

    def save(self, *args, **kwargs):
        # Inherit organisation from the parent asset when not set explicitly.
        if self.organisation_id is None and self.asset_id is not None:
            self.organisation_id = self.asset.organisation_id
        super().save(*args, **kwargs)

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
    
    organisation = models.ForeignKey(
        Organisation, on_delete=models.CASCADE, related_name='library_checks'
    )
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

    def save(self, *args, **kwargs):
        if self.organisation_id is None and self.scan_id is not None:
            self.organisation_id = self.scan.organisation_id
        super().save(*args, **kwargs)

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
    
    organisation = models.ForeignKey(
        Organisation, on_delete=models.CASCADE, related_name='ssl_checks'
    )
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

    def save(self, *args, **kwargs):
        if self.organisation_id is None and self.scan_id is not None:
            self.organisation_id = self.scan.organisation_id
        super().save(*args, **kwargs)

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
    
    organisation = models.ForeignKey(
        Organisation, on_delete=models.CASCADE, related_name='email_checks'
    )
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

    def save(self, *args, **kwargs):
        if self.organisation_id is None and self.scan_id is not None:
            self.organisation_id = self.scan.organisation_id
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.check_type} - {self.status}"


class SecurityHeaderCheck(models.Model):
    """Security headers checks"""
    STATUS_CHOICES = [
        ('missing', 'Missing'),
        ('present', 'Present'),
        ('misconfigured', 'Misconfigured'),
    ]
    
    organisation = models.ForeignKey(
        Organisation, on_delete=models.CASCADE, related_name='header_checks'
    )
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

    def save(self, *args, **kwargs):
        if self.organisation_id is None and self.scan_id is not None:
            self.organisation_id = self.scan.organisation_id
        super().save(*args, **kwargs)

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
    
    organisation = models.ForeignKey(
        Organisation, on_delete=models.CASCADE, related_name='dns_checks'
    )
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

    def save(self, *args, **kwargs):
        if self.organisation_id is None and self.scan_id is not None:
            self.organisation_id = self.scan.organisation_id
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.check_type} - {self.asset.value}"

class TechnologyCheck(models.Model):
    organisation = models.ForeignKey(
        Organisation, on_delete=models.CASCADE, related_name='technology_checks'
    )
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

    def save(self, *args, **kwargs):
        if self.organisation_id is None and self.scan_id is not None:
            self.organisation_id = self.scan.organisation_id
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.technology_name} {self.version}"


# ============================================
# MAINTENANCE HELPERS
# ============================================

def finalize_stale_scans(timeout_minutes=None, organisation=None):
    """Finalize orphaned scans stuck in 'running'/'queued'.

    Scans run synchronously inside the HTTP request, so a server restart (or a
    killed worker) can leave a scan in 'running' forever with no process left to
    finalize it. This sweeps any scan whose start is older than the timeout and
    marks it 'cancelled' (if cancellation was requested) or 'failed' otherwise.

    Real scans complete in minutes, so the default timeout is deliberately well
    above that. Safe to call frequently — it only touches genuinely stale rows.
    Returns the number of scans finalized.
    """
    if timeout_minutes is None:
        timeout_minutes = getattr(settings, 'SCAN_STALE_TIMEOUT_MINUTES', 120)

    cutoff = timezone.now() - timedelta(minutes=timeout_minutes)
    qs = Scan.objects.filter(status__in=['queued', 'running']).filter(
        models.Q(started_at__lt=cutoff)
        | models.Q(started_at__isnull=True, created_at__lt=cutoff)
    )
    if organisation is not None:
        qs = qs.filter(organisation=organisation)

    count = 0
    for scan in qs:
        now = timezone.now()
        scan.status = 'cancelled' if scan.cancel_requested else 'failed'
        scan.finished_at = now
        reference = scan.started_at or scan.created_at
        scan.duration_seconds = int((now - reference).total_seconds()) if reference else 0
        scan.error_message = scan.error_message or (
            'Scan was interrupted (no active worker) and automatically finalized.'
        )
        scan.save(update_fields=['status', 'finished_at', 'duration_seconds', 'error_message'])
        count += 1
    return count