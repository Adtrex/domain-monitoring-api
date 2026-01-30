from rest_framework import viewsets, status
from rest_framework.decorators import action, api_view
from rest_framework.response import Response
from rest_framework.pagination import PageNumberPagination
from django.shortcuts import get_object_or_404
from django.db.models import Count, Q
from django.utils import timezone
from datetime import timedelta
import json
import logging

from .models import (
    Domain, Asset, Scan, ScanAsset, Finding, ScanFinding, CVE, FindingCVE,
    FrontendLibraryCheck, SSLTLSCheck, EmailSecurityCheck,
    SecurityHeaderCheck, DNSSecurityCheck
)
from .serializers import (
    DomainSerializer, AssetSerializer, ScanListSerializer, ScanDetailSerializer,
    ScanCreateSerializer, FindingSerializer, FrontendLibraryCheckSerializer,
    SSLTLSCheckSerializer, EmailSecurityCheckSerializer,
    SecurityHeaderCheckSerializer, DNSSecurityCheckSerializer,
    ScanResultSerializer, ScanSummarySerializer
)

# Import detection and scanning modules
from .nuclei_runner import run_nuclei_scan
from .cve_checker import check_library_vulnerabilities, get_ecosystem_for_library
from .library_detector import detect_technologies
from .org_extractor import extract_organization_name

logger = logging.getLogger(__name__)


class StandardPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = 'page_size'
    max_page_size = 100


# ============================================
# DOMAIN & ASSET VIEWSETS
# ============================================

class DomainViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing domains
    """
    queryset = Domain.objects.all()
    serializer_class = DomainSerializer
    pagination_class = StandardPagination


class AssetViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing assets
    """
    queryset = Asset.objects.all()
    serializer_class = AssetSerializer
    pagination_class = StandardPagination


# ============================================
# SCAN MANAGEMENT VIEWSET
# ============================================

class ScanViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing scans
    """
    queryset = Scan.objects.all()
    pagination_class = StandardPagination
    
    def get_serializer_class(self):
        if self.action == 'list':
            return ScanListSerializer
        elif self.action == 'create':
            return ScanCreateSerializer
        elif self.action == 'retrieve':
            return ScanResultSerializer
        return ScanDetailSerializer
    
    def create(self, request, *args, **kwargs):
        """
        Create and initiate a new scan
        POST /api/scans/
        Body: {
            "asset_ids": [1, 2, 3],
            "scan_type": "on-demand",
            "template_categories": ["ssl", "dns", "email"]
        }
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        asset_ids = serializer.validated_data['asset_ids']
        scan_type = serializer.validated_data.get('scan_type', 'on-demand')
        template_categories = serializer.validated_data.get('template_categories', [])
        
        # Validate assets exist
        assets = Asset.objects.filter(id__in=asset_ids)
        if assets.count() != len(asset_ids):
            return Response(
                {'error': 'One or more asset IDs not found'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Create scan
        scan = Scan.objects.create(
            scan_type=scan_type,
            status='queued',
            initiated_by=request.user.id if hasattr(request, 'user') else None
        )
        
        # Link assets to scan
        for asset in assets:
            ScanAsset.objects.create(scan=scan, asset=asset)
        
        return Response(
            ScanDetailSerializer(scan).data,
            status=status.HTTP_201_CREATED
        )
    
    @action(detail=True, methods=['get'])
    def summary(self, request, pk=None):
        """
        Get summary statistics for a scan
        GET /api/scans/{id}/summary/
        """
        scan = self.get_object()
        
        # Calculate summary statistics
        summary_data = {
            'scan_id': scan.id,
            'total_assets_scanned': scan.scan_assets.count(),
            
            # Finding counts by severity
            'total_findings': ScanFinding.objects.filter(scan=scan).count(),
            'critical_findings': ScanFinding.objects.filter(
                scan=scan, finding__risk_rating='Critical'
            ).count(),
            'high_findings': ScanFinding.objects.filter(
                scan=scan, finding__risk_rating='High'
            ).count(),
            'medium_findings': ScanFinding.objects.filter(
                scan=scan, finding__risk_rating='Medium'
            ).count(),
            'low_findings': ScanFinding.objects.filter(
                scan=scan, finding__risk_rating='Low'
            ).count(),
            
            # Check type counts
            'library_checks_count': scan.library_checks.count(),
            'ssl_checks_count': scan.ssl_checks.count(),
            'email_checks_count': scan.email_checks.count(),
            'header_checks_count': scan.header_checks.count(),
            'dns_checks_count': scan.dns_checks.count(),
            
            # Library statistics
            'libraries_up_to_date': scan.library_checks.filter(
                vulnerability_status='up-to-date'
            ).count(),
            'libraries_outdated': scan.library_checks.filter(
                vulnerability_status='outdated'
            ).count(),
            'libraries_vulnerable': scan.library_checks.filter(
                vulnerability_status='vulnerable'
            ).count(),
            
            # Email security status
            'spf_status': self._get_email_check_status(scan, 'SPF'),
            'dkim_status': self._get_email_check_status(scan, 'DKIM'),
            'dmarc_status': self._get_email_check_status(scan, 'DMARC'),
            
            # SSL statistics
            'ssl_issues_found': scan.ssl_checks.filter(
                cvss_score__gte=4.0
            ).count(),
            'weak_ciphers_detected': scan.ssl_checks.filter(
                check_type='cipher', 
                risk_rating__in=['High', 'Critical']
            ).exists(),
            'certificate_expiring_soon': scan.ssl_checks.filter(
                check_type='certificate',
                certificate_days_remaining__lte=30
            ).exists(),
            
            # Header statistics
            'missing_headers': scan.header_checks.filter(status='missing').count(),
            'present_headers': scan.header_checks.filter(status='present').count(),
        }
        
        serializer = ScanSummarySerializer(summary_data)
        return Response(serializer.data)
    
    def _get_email_check_status(self, scan, check_type):
        """Helper to get email check status"""
        check = scan.email_checks.filter(check_type=check_type).first()
        return check.status if check else 'NOT_CHECKED'

    @action(detail=True, methods=['post'])
    def execute(self, request, pk=None):
        """
        Execute a queued scan
        POST /api/scans/{id}/execute/
        """
        scan = self.get_object()
        
        if scan.status != 'queued':
            return Response(
                {'error': f'Cannot execute scan with status: {scan.status}'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Get scan parameters
        templates = request.data.get('templates', ['ssl', 'dns', 'email'])
        check_libraries = request.data.get('check_libraries', True)
        check_cves = request.data.get('check_cves', True)
        extract_org = request.data.get('extract_org', True)
        
        # Get assets
        scan_assets = ScanAsset.objects.filter(scan=scan).select_related('asset')
        assets = [sa.asset for sa in scan_assets]
        
        # Update status
        scan.status = 'running'
        scan.started_at = timezone.now()
        scan.save()
        
        try:
            # Execute scan (same logic as execute_nuclei_scan)
            for asset in assets:
                results = run_nuclei_scan(asset.value, templates=templates)
                _process_nuclei_results(scan, asset, results, templates)
                
                if check_libraries:
                    # Library detection logic here
                    pass
            
            scan.status = 'completed'
            scan.finished_at = timezone.now()
            scan.duration_seconds = int((scan.finished_at - scan.started_at).total_seconds())
            scan.save()
            
            return Response({
                'message': 'Scan executed successfully',
                'scan_id': scan.id,
                'status': 'completed',
                'duration_seconds': scan.duration_seconds
            })
        
        except Exception as e:
            scan.status = 'failed'
            scan.error_message = str(e)
            scan.save()
            return Response({'error': str(e)}, status=500)

# ============================================
# SEPARATE ENDPOINTS FOR EACH CHECK TYPE
# ============================================

@api_view(['GET'])
def scan_library_checks(request, scan_id):
    """
    Get frontend library checks for a scan
    GET /api/scans/{scan_id}/library-checks/
    """
    scan = get_object_or_404(Scan, id=scan_id)
    checks = FrontendLibraryCheck.objects.filter(scan=scan).select_related('asset')
    
    # Optional filtering
    risk_level = request.GET.get('risk_level')
    if risk_level:
        checks = checks.filter(risk_level=risk_level)
    
    status_filter = request.GET.get('status')
    if status_filter:
        checks = checks.filter(vulnerability_status=status_filter)
    
    serializer = FrontendLibraryCheckSerializer(checks, many=True)
    return Response({
        'scan_id': scan_id,
        'count': checks.count(),
        'checks': serializer.data
    })


@api_view(['GET'])
def scan_ssl_checks(request, scan_id):
    """
    Get SSL/TLS checks for a scan
    GET /api/scans/{scan_id}/ssl-checks/
    """
    scan = get_object_or_404(Scan, id=scan_id)
    checks = SSLTLSCheck.objects.filter(scan=scan).select_related('asset')
    
    # Optional filtering
    check_type = request.GET.get('check_type')
    if check_type:
        checks = checks.filter(check_type=check_type)
    
    risk_level = request.GET.get('risk_level')
    if risk_level:
        checks = checks.filter(risk_rating=risk_level)
    
    serializer = SSLTLSCheckSerializer(checks, many=True)
    return Response({
        'scan_id': scan_id,
        'count': checks.count(),
        'checks': serializer.data
    })


@api_view(['GET'])
def scan_email_checks(request, scan_id):
    """
    Get email security checks for a scan
    GET /api/scans/{scan_id}/email-checks/
    """
    scan = get_object_or_404(Scan, id=scan_id)
    checks = EmailSecurityCheck.objects.filter(scan=scan).select_related('asset')
    
    # Optional filtering
    check_type = request.GET.get('check_type')
    if check_type:
        checks = checks.filter(check_type=check_type)
    
    status_filter = request.GET.get('status')
    if status_filter:
        checks = checks.filter(status=status_filter)
    
    serializer = EmailSecurityCheckSerializer(checks, many=True)
    return Response({
        'scan_id': scan_id,
        'count': checks.count(),
        'checks': serializer.data
    })


@api_view(['GET'])
def scan_header_checks(request, scan_id):
    """
    Get security header checks for a scan
    GET /api/scans/{scan_id}/header-checks/
    """
    scan = get_object_or_404(Scan, id=scan_id)
    checks = SecurityHeaderCheck.objects.filter(scan=scan).select_related('asset')
    
    # Optional filtering
    status_filter = request.GET.get('status')
    if status_filter:
        checks = checks.filter(status=status_filter)
    
    risk_level = request.GET.get('risk_level')
    if risk_level:
        checks = checks.filter(risk_rating=risk_level)
    
    serializer = SecurityHeaderCheckSerializer(checks, many=True)
    return Response({
        'scan_id': scan_id,
        'count': checks.count(),
        'checks': serializer.data
    })


@api_view(['GET'])
def scan_dns_checks(request, scan_id):
    """
    Get DNS security checks for a scan
    GET /api/scans/{scan_id}/dns-checks/
    """
    scan = get_object_or_404(Scan, id=scan_id)
    checks = DNSSecurityCheck.objects.filter(scan=scan).select_related('asset')
    
    # Optional filtering
    check_type = request.GET.get('check_type')
    if check_type:
        checks = checks.filter(check_type=check_type)
    
    risk_level = request.GET.get('risk_level')
    if risk_level:
        checks = checks.filter(risk_rating=risk_level)
    
    serializer = DNSSecurityCheckSerializer(checks, many=True)
    return Response({
        'scan_id': scan_id,
        'count': checks.count(),
        'checks': serializer.data
    })


@api_view(['GET'])
def scan_findings(request, scan_id):
    """
    Get all findings for a scan
    GET /api/scans/{scan_id}/findings/
    """
    scan = get_object_or_404(Scan, id=scan_id)
    scan_findings = ScanFinding.objects.filter(scan=scan).select_related('finding')
    
    # Optional filtering
    category = request.GET.get('category')
    risk_rating = request.GET.get('risk_rating')
    status_filter = request.GET.get('status')
    
    findings = [sf.finding for sf in scan_findings]
    
    if category:
        findings = [f for f in findings if f.category == category]
    if risk_rating:
        findings = [f for f in findings if f.risk_rating == risk_rating]
    if status_filter:
        findings = [f for f in findings if f.status == status_filter]
    
    serializer = FindingSerializer(findings, many=True)
    return Response({
        'scan_id': scan_id,
        'count': len(findings),
        'findings': serializer.data
    })


# ============================================
# NUCLEI SCAN EXECUTION WITH LIBRARY & CVE CHECKS
# ============================================

@api_view(['POST'])
def execute_nuclei_scan(request):
    """
    Execute comprehensive security scan including:
    - Nuclei vulnerability scanning
    - Frontend library detection
    - CVE vulnerability checking
    - Organization name extraction
    
    POST /api/nuclei/scan/
    Body: {
        "asset_ids": [1, 2],
        "templates": ["ssl", "dns", "email", "headers"],
        "scan_type": "on-demand",
        "check_libraries": true,
        "check_cves": true,
        "extract_org": true
    }
    """
    asset_ids = request.data.get('asset_ids', [])
    templates = request.data.get('templates', ['ssl'])
    scan_type = request.data.get('scan_type', 'on-demand')
    check_libraries = request.data.get('check_libraries', True)
    check_cves = request.data.get('check_cves', True)
    extract_org = request.data.get('extract_org', True)
    
    if not asset_ids:
        return Response(
            {'error': 'asset_ids required'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Get assets
    assets = Asset.objects.filter(id__in=asset_ids)
    if not assets.exists():
        return Response(
            {'error': 'No valid assets found'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Create scan record
    scan = Scan.objects.create(
        scan_type=scan_type,
        status='running',
        started_at=timezone.now()
    )
    
    # Link assets
    for asset in assets:
        ScanAsset.objects.create(scan=scan, asset=asset)
    
    try:
        # Execute scans for each asset
        for asset in assets:
            logger.info(f"Starting scan for asset: {asset.value}")
            
            # 1. Extract organization name if requested
            if extract_org and not asset.domain.owner:
                logger.info(f"Extracting organization name for {asset.value}")
                org_name = extract_organization_name(asset.value)
                if org_name:
                    asset.domain.owner = org_name
                    asset.domain.save()
                    logger.info(f"Organization detected: {org_name}")
            
            # 2. Run Nuclei scan
            logger.info(f"Running Nuclei scan on {asset.value}")
            results = run_nuclei_scan(asset.value, templates=templates)
            _process_nuclei_results(scan, asset, results, templates)
            
            # 3. Check for libraries and CVEs
            if check_libraries:
                logger.info(f"Detecting libraries for {asset.value}")
                
                try:
                    # Detect libraries and CMS
                    tech_result = detect_technologies(asset.value)
                    detected_libraries = tech_result.get('libraries', [])
                    detected_cms = tech_result.get('cms')
                    
                    logger.info(f"Detected {len(detected_libraries)} libraries")
                    
                    # Process each library
                    for lib in detected_libraries:
                        lib_name = lib.get('name')
                        lib_version = lib.get('version')
                        
                        # Skip if no version
                        if not lib_version or lib_version.lower() in ['unknown', 'latest']:
                            logger.warning(f"Skipping {lib_name} - no version detected")
                            continue
                        
                        # Check for CVEs if enabled
                        vulnerabilities = []
                        vuln_status = 'up-to-date'
                        risk_level = 'Low'
                        max_cvss = 0.0
                        
                        if check_cves:
                            logger.info(f"Checking CVEs for {lib_name}@{lib_version}")
                            
                            try:
                                # Get ecosystem
                                ecosystem = get_ecosystem_for_library(lib_name)
                                
                                # Check vulnerabilities
                                cve_result = check_library_vulnerabilities(
                                    lib_name.lower(),
                                    lib_version,
                                    ecosystem
                                )
                                
                                vulnerabilities = cve_result.get('vulnerabilities', [])
                                max_cvss = cve_result.get('max_cvss_score', 0.0)
                                
                                if vulnerabilities:
                                    vuln_status = 'vulnerable'
                                    
                                    # Determine risk level from CVSS
                                    if max_cvss >= 9.0:
                                        risk_level = 'Critical'
                                    elif max_cvss >= 7.0:
                                        risk_level = 'High'
                                    elif max_cvss >= 4.0:
                                        risk_level = 'Medium'
                                    else:
                                        risk_level = 'Low'
                                    
                                    logger.info(f"Found {len(vulnerabilities)} CVEs for {lib_name} (Max CVSS: {max_cvss})")
                                else:
                                    logger.info(f"No CVEs found for {lib_name}@{lib_version}")
                            
                            except Exception as e:
                                logger.error(f"CVE check failed for {lib_name}: {e}")
                        
                        # Create library check record (avoid duplicates)
                        existing_check = FrontendLibraryCheck.objects.filter(
                            scan=scan,
                            asset=asset,
                            library_name=lib_name,
                            detected_version=lib_version
                        ).first()
                        
                        if not existing_check:
                            library_check = FrontendLibraryCheck.objects.create(
                                scan=scan,
                                asset=asset,
                                library_name=lib_name,
                                detected_version=lib_version,
                                latest_version='Unknown',
                                vulnerability_status=vuln_status,
                                risk_level=risk_level,
                                source_urls=[lib.get('source_url', asset.value)],
                                recommendation=f"{'Update immediately' if risk_level in ['Critical', 'High'] else 'Monitor'} {lib_name}"
                            )
                            logger.info(f"Created library check: {lib_name} v{lib_version} - {vuln_status}")
                        
                        # Create findings and link CVEs
                        for vuln in vulnerabilities:
                            cve_id = (
                                vuln.get('cve_id') or 
                                vuln.get('primary_cve') or 
                                vuln.get('id', 'UNKNOWN')
                            )
                            
                            cvss_score = vuln.get('cvss_score', 0.0)
                            cvss_vector = vuln.get('cvss_vector', '')
                            
                            # Get or create CVE record
                            if cve_id and cve_id.startswith('CVE-'):
                                cve_record, created = CVE.objects.get_or_create(
                                    cve_id=cve_id,
                                    defaults={
                                        'cvss_score': cvss_score,
                                        'cvss_vector': cvss_vector,
                                        'description': vuln.get('summary', vuln.get('description', vuln.get('details', '')))[:500],
                                        'published_date': vuln.get('published'),
                                        'last_modified': vuln.get('modified')
                                    }
                                )
                                
                                if created:
                                    logger.info(f"Created new CVE record: {cve_id}")
                                
                                # Check if finding already exists
                                existing_finding = Finding.objects.filter(
                                    asset=asset,
                                    title__icontains=f"{lib_name} {lib_version} - {cve_id}"
                                ).first()
                                
                                if not existing_finding:
                                    # Create finding
                                    finding = Finding.objects.create(
                                        asset=asset,
                                        title=f"{lib_name} {lib_version} - {cve_id}",
                                        category='CVE',
                                        nuclei_template_id='library-cve-check',
                                        nuclei_severity=vuln.get('severity', 'medium').lower(),
                                        cvss_score=cvss_score,
                                        cvss_vector=cvss_vector,
                                        risk_rating=risk_level,
                                        scoring_confidence='High',
                                        evidence=f"Vulnerable library: {lib_name} v{lib_version}",
                                        recommendation=vuln.get('details', f'Update {lib_name} to a patched version')[:500],
                                        status='open'
                                    )
                                    
                                    # Link finding to scan
                                    ScanFinding.objects.create(scan=scan, finding=finding)
                                    
                                    # Link finding to CVE
                                    FindingCVE.objects.create(
                                        finding=finding,
                                        cve=cve_record,
                                        relevance='direct'
                                    )
                                    
                                    logger.info(f"Created finding for {cve_id}")
                    
                    # Store CMS info if detected
                    if detected_cms:
                        logger.info(f"Detected CMS: {detected_cms['name']} v{detected_cms['version']}")
                        
                        # Create informational finding for CMS
                        if detected_cms['version'] not in ['Unknown', 'SaaS']:
                            existing_cms_finding = Finding.objects.filter(
                                asset=asset,
                                title__icontains=f"{detected_cms['name']} CMS"
                            ).first()
                            
                            if not existing_cms_finding:
                                finding = Finding.objects.create(
                                    asset=asset,
                                    title=f"{detected_cms['name']} CMS Detected - {detected_cms['version']}",
                                    category='Misconfiguration',
                                    nuclei_template_id='cms-detection',
                                    nuclei_severity='info',
                                    risk_rating='Low',
                                    scoring_confidence='High',
                                    evidence=f"CMS: {detected_cms['name']} v{detected_cms['version']}",
                                    recommendation=f"Ensure {detected_cms['name']} is up to date and properly configured",
                                    status='open'
                                )
                                ScanFinding.objects.create(scan=scan, finding=finding)
                
                except Exception as e:
                    logger.error(f"Library/CVE detection failed for {asset.value}: {e}")
        
        # Mark scan as completed
        scan.status = 'completed'
        scan.finished_at = timezone.now()
        scan.duration_seconds = (scan.finished_at - scan.started_at).total_seconds()
        scan.save()
        
        logger.info(f"Scan {scan.id} completed successfully in {scan.duration_seconds}s")
        
        return Response({
            'message': 'Scan completed successfully',
            'scan_id': scan.id,
            'status': 'completed',
            'duration_seconds': scan.duration_seconds
        })
        
    except Exception as e:
        logger.error(f"Scan {scan.id} failed: {e}")
        scan.status = 'failed'
        scan.error_message = str(e)
        scan.finished_at = timezone.now()
        scan.save()
        
        return Response(
            {'error': f'Scan failed: {str(e)}'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


def _process_nuclei_results(scan, asset, results, templates):
    """
    Process Nuclei scan results and store in appropriate tables
    WITH DEDUPLICATION
    """
    # Track processed findings to avoid duplicates
    processed_findings = set()
    
    for result in results:
        template_id = result.get('template-id', '')
        template_name = result.get('info', {}).get('name', '')
        severity = result.get('info', {}).get('severity', 'info')
        
        # Create unique key for deduplication
        finding_key = f"{template_id}_{asset.id}_{template_name}"
        
        # Skip if already processed
        if finding_key in processed_findings:
            logger.debug(f"Skipping duplicate finding: {template_name}")
            continue
        
        processed_findings.add(finding_key)
        
        # Determine check type based on template
        if 'ssl' in template_id.lower() or 'tls' in template_id.lower():
            _create_ssl_check(scan, asset, result)
        elif 'dns' in template_id.lower():
            _create_dns_check(scan, asset, result)
        elif 'email' in template_id.lower() or 'spf' in template_id.lower() or 'dmarc' in template_id.lower():
            _create_email_check(scan, asset, result)
        elif 'header' in template_id.lower():
            _create_header_check(scan, asset, result)
        elif 'javascript' in template_id.lower() or 'library' in template_id.lower():
            _create_library_check(scan, asset, result)
        
        # Also create a Finding record
        _create_finding(scan, asset, result)


def _create_ssl_check(scan, asset, result):
    """Create SSL/TLS check record with deduplication"""
    template_id = result.get('template-id', '')
    info = result.get('info', {})
    
    # Determine check type
    if 'certificate' in template_id or 'cert' in template_id:
        check_type = 'certificate'
    elif 'cipher' in template_id:
        check_type = 'cipher'
    elif 'protocol' in template_id or 'tls-version' in template_id:
        check_type = 'protocol'
    else:
        check_type = 'hsts'
    
    finding_name = info.get('name', '')
    
    # Check for duplicate
    existing = SSLTLSCheck.objects.filter(
        scan=scan,
        asset=asset,
        check_type=check_type,
        finding=finding_name
    ).first()
    
    if existing:
        logger.debug(f"Skipping duplicate SSL check: {finding_name}")
        return
    
    SSLTLSCheck.objects.create(
        scan=scan,
        asset=asset,
        check_type=check_type,
        finding=finding_name,
        example=result.get('matched-at', ''),
        cvss_score=info.get('classification', {}).get('cvss-score', 0.0),
        risk_rating=_map_severity_to_risk(info.get('severity', 'info')),
        recommendation=info.get('remediation', '')
    )


def _create_dns_check(scan, asset, result):
    """Create DNS check record with deduplication"""
    template_id = result.get('template-id', '')
    info = result.get('info', {})
    
    # Determine check type
    if 'dnssec' in template_id:
        check_type = 'dnssec'
    elif 'zone-transfer' in template_id or 'axfr' in template_id:
        check_type = 'zone_transfer'
    elif 'hijack' in template_id:
        check_type = 'hijacking'
    else:
        check_type = 'subdomain_takeover'
    
    finding_name = info.get('name', '')
    
    # Check for duplicate
    existing = DNSSecurityCheck.objects.filter(
        scan=scan,
        asset=asset,
        check_type=check_type,
        finding=finding_name
    ).first()
    
    if existing:
        return
    
    DNSSecurityCheck.objects.create(
        scan=scan,
        asset=asset,
        check_type=check_type,
        finding=finding_name,
        example=result.get('matched-at', ''),
        cvss_score=info.get('classification', {}).get('cvss-score', 0.0),
        risk_rating=_map_severity_to_risk(info.get('severity', 'info')),
        recommendation=info.get('remediation', '')
    )


def _create_email_check(scan, asset, result):
    """Create email security check record with deduplication"""
    template_id = result.get('template-id', '').lower()
    info = result.get('info', {})
    
    # Determine check type
    if 'spf' in template_id:
        check_type = 'SPF'
    elif 'dkim' in template_id:
        check_type = 'DKIM'
    else:
        check_type = 'DMARC'
    
    # Check for duplicate
    existing = EmailSecurityCheck.objects.filter(
        scan=scan,
        asset=asset,
        check_type=check_type
    ).first()
    
    if existing:
        return
    
    # Determine status
    severity = info.get('severity', 'info')
    status_value = 'FAIL' if severity in ['high', 'critical', 'medium'] else 'PASS'
    
    EmailSecurityCheck.objects.create(
        scan=scan,
        asset=asset,
        check_type=check_type,
        status=status_value,
        details=info.get('description', ''),
        cvss_score=info.get('classification', {}).get('cvss-score', 0.0),
        risk_rating=_map_severity_to_risk(severity),
        recommendation=info.get('remediation', ''),
        record_value=result.get('extracted-results', [''])[0] if result.get('extracted-results') else ''
    )


def _create_header_check(scan, asset, result):
    """Create security header check record with deduplication"""
    info = result.get('info', {})
    header_name = result.get('matcher-name', '') or info.get('name', '')
    
    # Check for duplicate
    existing = SecurityHeaderCheck.objects.filter(
        scan=scan,
        asset=asset,
        header=header_name
    ).first()
    
    if existing:
        return
    
    SecurityHeaderCheck.objects.create(
        scan=scan,
        asset=asset,
        header=header_name,
        status='missing',
        cvss_score=info.get('classification', {}).get('cvss-score', 0.0),
        risk_rating=_map_severity_to_risk(info.get('severity', 'info')),
        recommendation=info.get('remediation', ''),
        header_value=''
    )


def _create_library_check(scan, asset, result):
    """Create frontend library check record with deduplication"""
    info = result.get('info', {})
    
    library_name = result.get('matcher-name', 'unknown')
    detected_version = result.get('extracted-results', ['unknown'])[0] if result.get('extracted-results') else 'unknown'
    
    # Check for duplicate
    existing = FrontendLibraryCheck.objects.filter(
        scan=scan,
        asset=asset,
        library_name=library_name,
        detected_version=detected_version
    ).first()
    
    if existing:
        return
    
    FrontendLibraryCheck.objects.create(
        scan=scan,
        asset=asset,
        library_name=library_name,
        detected_version=detected_version,
        latest_version='unknown',
        vulnerability_status='vulnerable' if info.get('severity') in ['high', 'critical'] else 'outdated',
        risk_level=_map_severity_to_risk(info.get('severity', 'info')),
        source_urls=[result.get('matched-at', '')],
        recommendation=info.get('remediation', '')
    )


def _create_finding(scan, asset, result):
    """Create general finding record with deduplication"""
    info = result.get('info', {})
    title = info.get('name', '')
    template_id = result.get('template-id', '')
    
    # Check for duplicate
    existing = Finding.objects.filter(
        asset=asset,
        title=title,
        nuclei_template_id=template_id
    ).first()
    
    if existing:
        # Just link existing finding to this scan
        ScanFinding.objects.get_or_create(scan=scan, finding=existing)
        return
    
    finding = Finding.objects.create(
        asset=asset,
        title=title,
        category=_determine_category(template_id),
        nuclei_template_id=template_id,
        nuclei_severity=info.get('severity', 'info'),
        cvss_score=info.get('classification', {}).get('cvss-score'),
        cvss_vector=info.get('classification', {}).get('cvss-metrics'),
        risk_rating=_map_severity_to_risk(info.get('severity', 'info')),
        scoring_confidence='High',
        evidence=result.get('matched-at', ''),
        recommendation=info.get('remediation', ''),
        status='open'
    )
    
    # Link to scan
    ScanFinding.objects.create(scan=scan, finding=finding)


def _map_severity_to_risk(severity):
    """Map Nuclei severity to risk rating"""
    severity_map = {
        'critical': 'Critical',
        'high': 'High',
        'medium': 'Medium',
        'low': 'Low',
        'info': 'Low'
    }
    return severity_map.get(severity.lower(), 'Low')


def _determine_category(template_id):
    """Determine finding category from template ID"""
    template_id = template_id.lower()
    
    if 'cve' in template_id:
        return 'CVE'
    elif 'ssl' in template_id or 'tls' in template_id:
        return 'SSL'
    elif 'dns' in template_id:
        return 'DNS'
    elif 'email' in template_id or 'spf' in template_id or 'dmarc' in template_id:
        return 'Email'
    else:
        return 'Misconfiguration'


# ============================================
# DASHBOARD & STATISTICS
# ============================================

@api_view(['GET'])
def dashboard_metrics(request):
    """
    Get dashboard metrics
    GET /api/dashboard/metrics/
    """
    total_scans = Scan.objects.count()
    completed_scans = Scan.objects.filter(status='completed').count()
    
    # Get findings by risk level
    findings_by_risk = Finding.objects.values('risk_rating').annotate(
        count=Count('id')
    )
    
    # Recent scans
    recent_scans = Scan.objects.filter(
        created_at__gte=timezone.now() - timedelta(days=7)
    ).count()
    
    return Response({
        'total_scans': total_scans,
        'completed_scans': completed_scans,
        'failed_scans': Scan.objects.filter(status='failed').count(),
        'recent_scans_week': recent_scans,
        'findings_by_risk': {item['risk_rating']: item['count'] for item in findings_by_risk},
        'total_assets': Asset.objects.count(),
        'total_domains': Domain.objects.count(),
    })