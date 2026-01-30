from rest_framework import serializers
from .models import (
    Domain, Asset, Scan, ScanAsset, Finding, ScanFinding, CVE, FindingCVE,
    FrontendLibraryCheck, SSLTLSCheck, EmailSecurityCheck, 
    SecurityHeaderCheck, DNSSecurityCheck
)


# ============================================
# DOMAIN & ASSET SERIALIZERS
# ============================================

class DomainSerializer(serializers.ModelSerializer):
    class Meta:
        model = Domain
        fields = '__all__'


class AssetSerializer(serializers.ModelSerializer):
    class Meta:
        model = Asset
        fields = '__all__'


# ============================================
# SCAN SERIALIZERS
# ============================================

class ScanListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for scan lists"""
    class Meta:
        model = Scan
        fields = [
            'id', 'scan_type', 'status', 'started_at', 
            'finished_at', 'duration_seconds', 'created_at'
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
    
    class Meta:
        model = FrontendLibraryCheck
        fields = [
            'id', 'scan', 'asset', 'asset_url', 'library_name', 
            'detected_version', 'latest_version', 'vulnerability_status',
            'risk_level', 'source_urls', 'recommendation', 'checked_at'
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
    findings = serializers.SerializerMethodField()
    
    class Meta:
        model = Scan
        fields = [
            'id', 'scan_type', 'status', 'started_at', 'finished_at',
            'duration_seconds', 'error_message', 'created_at',
            'library_checks', 'ssl_checks', 'email_checks',
            'header_checks', 'dns_checks', 'findings'
        ]
    
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