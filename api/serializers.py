from rest_framework import serializers

from .models import TechnologyCheck
from .models import (
    Domain, Asset, Scan, ScanAsset, Finding, ScanFinding, CVE, FindingCVE,
    FrontendLibraryCheck, SSLTLSCheck, EmailSecurityCheck, 
    SecurityHeaderCheck, DNSSecurityCheck, ReportSummary, ReportSummaryFinding
)
# ============================================
# DOMAIN & ASSET SERIALIZERS
# ============================================

# ============================================
# REPORT SUMMARY SERIALIZER
# ============================================
class ReportSummarySerializer(serializers.ModelSerializer):
    class Meta:
        model = ReportSummary
        fields = '__all__'


class ReportSummaryFindingSerializer(serializers.ModelSerializer):
    class Meta:
        model = ReportSummaryFinding
        fields = '__all__'


# ============================================
# DOMAIN & ASSET SERIALIZERS
# ============================================

class DomainSerializer(serializers.ModelSerializer):
    class Meta:
        model = Domain
        fields = '__all__'
        # organisation is assigned server-side from the caller's token, never by the client.
        read_only_fields = ['organisation']


class AssetSerializer(serializers.ModelSerializer):
    class Meta:
        model = Asset
        fields = '__all__'
        # organisation is assigned server-side from the caller's token, never by the client.
        read_only_fields = ['organisation']


# ============================================
# SCAN SERIALIZERS
# ============================================

class ScanListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for scan lists"""
    class Meta:
        model = Scan
        fields = [
            'id', 'scan_type', 'status', 'started_at', 
            'finished_at', 'duration_seconds', 'cancel_requested', 'created_at'
        ]


class ScanDetailSerializer(serializers.ModelSerializer):
    """Detailed scan information"""
    class Meta:
        model = Scan
        fields = '__all__'


class ScanCreateSerializer(serializers.Serializer):
    """Serializer for creating new scans"""
    asset_ids = serializers.ListField(
        child=serializers.IntegerField(),
        required=True
    )
    scan_type = serializers.ChoiceField(
        choices=['on-demand', 'scheduled', 'triggered'],
        default='on-demand'
    )
    template_categories = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        allow_empty=True
    )


# ============================================
# FINDING SERIALIZERS
# ============================================

class CVESerializer(serializers.ModelSerializer):
    class Meta:
        model = CVE
        fields = '__all__'


class FindingSerializer(serializers.ModelSerializer):
    cves = CVESerializer(source='finding_cves', many=True, read_only=True)
    
    class Meta:
        model = Finding
        fields = '__all__'


# ============================================
# CHECK RESULT SERIALIZERS
# ============================================

class FrontendLibraryCheckSerializer(serializers.ModelSerializer):
    asset_url = serializers.CharField(source='asset.value', read_only=True)
    cvss_score = serializers.SerializerMethodField()

    def get_cvss_score(self, obj):
        """Derived CVSS score for frontend libraries when explicit CVSS is not persisted."""
        risk_to_cvss = {
            'Critical': 9.5,
            'High': 7.5,
            'Medium': 5.0,
            'Low': 2.5,
        }
        return risk_to_cvss.get(obj.risk_level, 0.0)
    
    class Meta:
        model = FrontendLibraryCheck
        fields = [
            'id', 'scan', 'asset', 'asset_url', 'library_name', 
            'detected_version', 'latest_version', 'vulnerability_status',
            'risk_level', 'cvss_score', 'source_urls', 'recommendation', 'checked_at'
        ]


class SSLTLSCheckSerializer(serializers.ModelSerializer):
    asset_url = serializers.CharField(source='asset.value', read_only=True)
    
    class Meta:
        model = SSLTLSCheck
        fields = [
            'id', 'scan', 'asset', 'asset_url', 'check_type', 'finding',
            'example', 'cvss_score', 'risk_rating', 'recommendation',
            'certificate_expiry', 'certificate_days_remaining',
            'protocols_supported', 'weak_ciphers', 'checked_at'
        ]


class EmailSecurityCheckSerializer(serializers.ModelSerializer):
    asset_url = serializers.CharField(source='asset.value', read_only=True)
    
    class Meta:
        model = EmailSecurityCheck
        fields = [
            'id', 'scan', 'asset', 'asset_url', 'check_type', 'status',
            'details', 'cvss_score', 'risk_rating', 'recommendation',
            'record_value', 'checked_at'
        ]


class SecurityHeaderCheckSerializer(serializers.ModelSerializer):
    asset_url = serializers.CharField(source='asset.value', read_only=True)
    
    class Meta:
        model = SecurityHeaderCheck
        fields = [
            'id', 'scan', 'asset', 'asset_url', 'header', 'status',
            'cvss_score', 'risk_rating', 'recommendation', 
            'header_value', 'checked_at'
        ]


class DNSSecurityCheckSerializer(serializers.ModelSerializer):
    asset_url = serializers.CharField(source='asset.value', read_only=True)
    
    class Meta:
        model = DNSSecurityCheck
        fields = [
            'id', 'scan', 'asset', 'asset_url', 'check_type', 'finding',
            'example', 'cvss_score', 'risk_rating', 'recommendation',
            'checked_at'
        ]


# ============================================
# COMPREHENSIVE SCAN RESULT SERIALIZER
# ============================================

class ScanResultSerializer(serializers.ModelSerializer):
    """Complete scan results with all checks"""
    library_checks = FrontendLibraryCheckSerializer(many=True, read_only=True)
    ssl_checks = SSLTLSCheckSerializer(many=True, read_only=True)
    email_checks = EmailSecurityCheckSerializer(many=True, read_only=True)
    header_checks = SecurityHeaderCheckSerializer(many=True, read_only=True)
    dns_checks = DNSSecurityCheckSerializer(many=True, read_only=True)
    checks = serializers.SerializerMethodField()
    findings = serializers.SerializerMethodField()
    
    class Meta:
        model = Scan
        fields = [
            'id', 'scan_type', 'status', 'started_at', 'finished_at',
            'duration_seconds', 'error_message', 'created_at',
            'library_checks', 'ssl_checks', 'email_checks',
            'header_checks', 'dns_checks', 'checks', 'findings'
        ]

    def _max_risk_level(self, levels):
        risk_order = {'Low': 0, 'Medium': 1, 'High': 2, 'Critical': 3}
        if not levels:
            return 'Low'
        return max(levels, key=lambda level: risk_order.get(level, 0))

    def get_checks(self, obj):
        library_checks = list(obj.library_checks.all())
        ssl_checks = list(obj.ssl_checks.all())
        email_checks = list(obj.email_checks.all())
        header_checks = list(obj.header_checks.all())

        library_details = [
            {
                'name': check.library_name,
                'detected_version': check.detected_version,
                'latest_version': check.latest_version,
                'status': check.vulnerability_status,
                'vulnerability': check.risk_level
            }
            for check in library_checks
        ]
        libraries_up_to_date = len(
            [check for check in library_checks if check.vulnerability_status == 'up-to-date']
        )
        libraries_outdated = len(library_checks) - libraries_up_to_date

        ssl_details = [
            {
                'name': check.finding or check.check_type,
                'type': check.check_type,
                'status': 'pass' if check.risk_rating == 'Low' else 'fail',
                'details': check.example or check.finding or 'N/A',
                'recommendation': check.recommendation or 'Review SSL/TLS configuration'
            }
            for check in ssl_checks
        ]
        ssl_passed = len([check for check in ssl_checks if check.risk_rating == 'Low'])
        ssl_failed = len(ssl_checks) - ssl_passed
        ssl_score = 100 if not ssl_checks else round(100 * (ssl_passed / len(ssl_checks)))

        email_details = [
            {
                'name': check.check_type,
                'type': check.check_type,
                'status': check.status.lower(),
                'details': check.details or 'N/A',
                'recommendation': check.recommendation or 'Review and configure'
            }
            for check in email_checks
        ]
        email_passed = len([check for check in email_checks if check.status == 'PASS'])
        email_failed = len(email_checks) - email_passed
        email_score = 100 if not email_checks else round(100 * (email_passed / len(email_checks)))

        missing_headers = [
            {
                'name': check.header,
                'risk': check.risk_rating or 'Medium',
                'recommendation': check.recommendation or f"Add {check.header} header"
            }
            for check in header_checks if check.status in ['missing', 'misconfigured']
        ]
        present_headers = [
            {
                'name': check.header,
                'value': check.header_value or 'Configured'
            }
            for check in header_checks if check.status == 'present'
        ]
        header_passed = len(present_headers)
        header_failed = len(missing_headers)
        header_total = len(header_checks)
        header_score = 100 if not header_checks else round(100 * (header_passed / header_total))

        return {
            'libraries': {
                'upToDate': libraries_up_to_date,
                'outdated': libraries_outdated,
                'details': library_details
            },
            'ssl': {
                'passed': ssl_passed,
                'failed': ssl_failed,
                'score': ssl_score,
                'riskLevel': self._max_risk_level([check.risk_rating for check in ssl_checks]),
                'details': ssl_details
            },
            'email': {
                'passed': email_passed,
                'failed': email_failed,
                'score': email_score,
                'riskLevel': self._max_risk_level([check.risk_rating for check in email_checks]),
                'details': email_details
            },
            'headers': {
                'passed': header_passed,
                'failed': header_failed,
                'score': header_score,
                'riskLevel': self._max_risk_level([check.risk_rating for check in header_checks]),
                'details': {
                    'missing': missing_headers,
                    'present': present_headers
                }
            }
        }
    
    def get_findings(self, obj):
        """Get all findings associated with this scan"""
        scan_findings = ScanFinding.objects.filter(scan=obj).select_related('finding')
        findings = [sf.finding for sf in scan_findings]
        return FindingSerializer(findings, many=True).data


# ============================================
# SCAN SUMMARY SERIALIZER
# ============================================

class ScanSummarySerializer(serializers.Serializer):
    """Summary statistics for a scan"""
    scan_id = serializers.IntegerField()
    total_assets_scanned = serializers.IntegerField()
    
    # Overall metrics
    total_findings = serializers.IntegerField()
    critical_findings = serializers.IntegerField()
    high_findings = serializers.IntegerField()
    medium_findings = serializers.IntegerField()
    low_findings = serializers.IntegerField()
    
    # Check type breakdown
    library_checks_count = serializers.IntegerField()
    ssl_checks_count = serializers.IntegerField()
    email_checks_count = serializers.IntegerField()
    header_checks_count = serializers.IntegerField()
    dns_checks_count = serializers.IntegerField()
    
    # Library specific
    libraries_up_to_date = serializers.IntegerField()
    libraries_outdated = serializers.IntegerField()
    libraries_vulnerable = serializers.IntegerField()
    
    # Email specific
    spf_status = serializers.CharField()
    dkim_status = serializers.CharField()
    dmarc_status = serializers.CharField()
    
    # SSL specific
    ssl_issues_found = serializers.IntegerField()
    weak_ciphers_detected = serializers.BooleanField()
    certificate_expiring_soon = serializers.BooleanField()
    
    # Headers specific
    missing_headers = serializers.IntegerField()
    present_headers = serializers.IntegerField()

class TechnologyCheckSerializer(serializers.ModelSerializer):
    asset_value = serializers.CharField(source='asset.value', read_only=True)

    class Meta:
        model = TechnologyCheck
        fields = '__all__'