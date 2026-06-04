from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from django.http import FileResponse
from django.shortcuts import get_object_or_404
from .models import Scan
from .detailed_report import generate_detailed_report_docx



from .models import (
    Asset, DNSSecurityCheck, EmailSecurityCheck, Finding, FrontendLibraryCheck, ScanAsset, SSLTLSCheck, SecurityHeaderCheck, TechnologyCheck
)
from .report_summary_views import _normalize_severity
from .report_external_links import get_external_reference

class DetailedReportExportView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, scan_id=None):
        scan_obj = get_object_or_404(Scan, id=scan_id)
        domain_obj = None
        assets = Asset.objects.filter(asset_scans__scan=scan_obj).distinct()
        if assets.exists():
            domain_obj = assets.first().domain

        # Use organization name from domain if available
        organization_name = None
        if domain_obj and hasattr(domain_obj, 'owner') and domain_obj.owner:
            organization_name = domain_obj.owner
        elif domain_obj and hasattr(domain_obj, 'root_domain'):
            organization_name = domain_obj.root_domain.upper()
        else:
            organization_name = "NITDA"

        report_title = "Digital Asset Security Assessment Report"
        executive_summary = f"This report provides a comprehensive breakdown of all findings for scan {scan_id}. Each section contains detailed explanations, risks, affected assets, and step-by-step remediation guidance."

        # Gather all findings and checks
        findings = list(Finding.objects.filter(finding_scans__scan=scan_obj).select_related('asset'))
        ssl_checks = list(SSLTLSCheck.objects.filter(scan=scan_obj).select_related('asset'))
        dns_checks = list(DNSSecurityCheck.objects.filter(scan=scan_obj).select_related('asset'))
        email_checks = list(EmailSecurityCheck.objects.filter(scan=scan_obj).select_related('asset'))
        header_checks = list(SecurityHeaderCheck.objects.filter(scan=scan_obj).select_related('asset'))
        library_checks = list(FrontendLibraryCheck.objects.filter(scan=scan_obj).select_related('asset'))
        tech_checks = list(TechnologyCheck.objects.filter(scan=scan_obj).select_related('asset'))

        # Group findings by category and severity
        categories = [
            ("SSL/TLS", ssl_checks),
            ("DNS", dns_checks),
            ("Email Security", email_checks),
            ("Security Headers", header_checks),
            ("Frontend Libraries", library_checks),
            ("Technologies", tech_checks),
            ("Other Findings", findings),
        ]

        grouped_findings = {}

        for cat, items in categories:
            cat_findings = []
            for row in items:
                # SSL/TLS
                if hasattr(row, 'check_type') and hasattr(row, 'finding'):
                    title = f"{row.check_type}: {row.finding[:80]}"
                    risk = row.finding or row.example or "SSL/TLS weakness identified."
                    affected_assets = [row.asset.value]
                    references = [get_external_reference(title, risk)]
                    # Detailed remediation for SSL/TLS
                    recommendations = [
                        "1. Disable all SSL 2.0, SSL 3.0, TLS 1.0, and TLS 1.1 protocols immediately.",
                        "2. Enforce TLS 1.2 as minimum, with TLS 1.3 preferred.",
                        "3. Disable weak cipher suites across all affected services.",
                        "4. If any of the above services are no longer in active use, decommission them properly: remove DNS records, shut down the service, revoke associated certificates, and close open ports.",
                        "5. Regularly test your SSL/TLS configuration using tools like SSL Labs or Mozilla SSL Config.",
                    ]
                    if hasattr(row, 'certificate_expiry') and row.certificate_expiry:
                        recommendations.append(f"6. Certificate expires on {row.certificate_expiry}. Renew before expiry.")
                    cat_findings.append({
                        "title": title,
                        "risk": risk,
                        "affected_assets": affected_assets,
                        "recommendations": recommendations,
                        "references": references,
                    })
                # DNS
                elif hasattr(row, 'check_type') and hasattr(row, 'finding') and hasattr(row, 'cvss_score') and hasattr(row, 'risk_rating') and hasattr(row, 'recommendation') and hasattr(row, 'asset'):
                    title = f"{row.check_type}: {row.finding[:80]}"
                    risk = row.finding or row.example or "DNS issue identified."
                    affected_assets = [row.asset.value]
                    references = [get_external_reference(title, risk)]
                    recommendations = [
                        "1. Update DNS records and remove stale or misconfigured entries.",
                        "2. Implement DNSSEC to protect against DNS spoofing and hijacking.",
                        "3. Regularly audit DNS records for unnecessary or legacy entries.",
                        "4. For subdomain takeover findings, remove unused subdomains and validate CNAME/A records.",
                        "5. Use monitoring to alert on unauthorized DNS changes.",
                    ]
                    cat_findings.append({
                        "title": title,
                        "risk": risk,
                        "affected_assets": affected_assets,
                        "recommendations": recommendations,
                        "references": references,
                    })
                # Email Security
                elif hasattr(row, 'check_type') and hasattr(row, 'status') and hasattr(row, 'details'):
                    title = f"{row.check_type}: {row.status}"
                    risk = row.details or f"{row.check_type} misconfiguration detected."
                    affected_assets = [row.asset.value]
                    references = [get_external_reference(title, risk)]
                    recommendations = [
                        "1. Correct SPF, DKIM, and DMARC records and verify alignment using online tools.",
                        "2. For SPF, use '-all' for hard fail and avoid '?all' or '~all' unless necessary.",
                        "3. For DKIM, ensure keys are at least 2048 bits and rotate them regularly.",
                        "4. For DMARC, start with p=quarantine, then move to p=reject after monitoring.",
                        "5. Monitor DMARC aggregate reports to detect unauthorized email sources.",
                        "6. Document and review all changes with your email administrator.",
                    ]
                    cat_findings.append({
                        "title": title,
                        "risk": risk,
                        "affected_assets": affected_assets,
                        "recommendations": recommendations,
                        "references": references,
                    })
                # Security Headers
                elif hasattr(row, 'header') and hasattr(row, 'status'):
                    title = f"{row.header}: {row.status}"
                    risk = f"Header {row.header} is {row.status}. {row.recommendation}"
                    affected_assets = [row.asset.value]
                    references = [get_external_reference(title, risk)]
                    header = (row.header or '').lower()
                    recommendations = []
                    if header == 'x-xss-protection':
                        recommendations = [
                            'Set "X-XSS-Protection: 1; mode=block" for legacy browser protection.',
                            'Test header application using browser developer tools.',
                        ]
                    elif header == 'permissions-policy':
                        recommendations = [
                            'Implement Permissions-Policy to restrict browser features and APIs.',
                            'Define only the features your application requires.',
                        ]
                    elif header == 'referrer-policy':
                        recommendations = [
                            'Set "Referrer-Policy: strict-origin-when-cross-origin" to control referrer information.',
                        ]
                    elif header == 'x-content-type-options':
                        recommendations = [
                            'Set "X-Content-Type-Options: nosniff" to prevent MIME type sniffing.',
                        ]
                    elif header == 'x-frame-options':
                        recommendations = [
                            'Set "X-Frame-Options: DENY" to prevent clickjacking attacks.',
                        ]
                    elif header == 'content-security-policy':
                        recommendations = [
                            'Implement Content-Security-Policy to prevent XSS and injection attacks.',
                            'Define script-src, style-src, img-src, and default-src directives with specific trusted domains.',
                            'Avoid wildcard values (*) in any CSP directive.',
                            'Deploy in report-only mode first (Content-Security-Policy-Report-Only) to identify breakage before enforcing.',
                        ]
                    elif header == 'strict-transport-security':
                        recommendations = [
                            'Enable HSTS to enforce HTTPS. Set "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload".',
                            'Begin with a shorter max-age (e.g., 300 seconds) during testing, then increase to 31536000 (1 year).',
                            'Once confident in full HTTPS coverage, consider submitting the domain to the HSTS preload list.',
                        ]
                    else:
                        recommendations = [
                            f'Apply the {row.header} header with a secure value at the web server layer.'
                        ]
                    cat_findings.append({
                        "title": title,
                        "risk": risk,
                        "affected_assets": affected_assets,
                        "recommendations": recommendations,
                        "references": references,
                    })
                # Frontend Libraries
                elif hasattr(row, 'library_name'):
                    title = f"{row.library_name} {row.detected_version} ({row.vulnerability_status})"
                    risk = f"Detected {row.vulnerability_status} library version on {row.asset.value}."
                    affected_assets = [row.asset.value]
                    references = [get_external_reference(title, risk), "https://owasp.org/www-project-top-ten/2017/A9_2017-Using_Components_with_Known_Vulnerabilities"]
                    recommendations = [
                        "1. Inventory all frontend libraries and frameworks in use.",
                        "2. Update the affected library or plugin to the latest patched version from an official source.",
                        "3. Remove unused or legacy libraries from your codebase.",
                        "4. Use tools like Snyk or GitHub Dependabot to monitor for new vulnerabilities.",
                        "5. Review release notes for breaking changes before upgrading.",
                        "6. Test all updates in a staging environment before deploying to production.",
                    ]
                    cat_findings.append({
                        "title": title,
                        "risk": risk,
                        "affected_assets": affected_assets,
                        "recommendations": recommendations,
                        "references": references,
                    })
                # Technologies
                elif hasattr(row, 'technology_name'):
                    title = f"{row.technology_name} {row.version}"
                    risk = f"Technology category: {row.category}. Detected version {row.version} is behind latest {row.latest_version}."
                    affected_assets = [row.asset.value]
                    references = [get_external_reference(title, risk), "https://csrc.nist.gov/publications/detail/sp/800-40/rev-3/final"]
                    recommendations = [
                        f"1. Maintain an inventory of all technologies and plugins in use.",
                        f"2. Upgrade {row.technology_name} from {row.version} to {row.latest_version} as soon as possible.",
                        "3. Remove or disable unused plugins/modules.",
                        "4. Subscribe to vendor security advisories for timely updates.",
                        "5. Use automated tools to monitor for vulnerabilities.",
                        "6. Test all upgrades in a staging environment before production deployment.",
                    ]
                    cat_findings.append({
                        "title": title,
                        "risk": risk,
                        "affected_assets": affected_assets,
                        "recommendations": recommendations,
                        "references": references,
                    })
                # Exposed Databases
                elif hasattr(row, 'service') and 'database' in (row.service or '').lower():
                    title = f"Exposed Database: {row.service} on {row.asset.value}"
                    risk = f"Publicly accessible database service detected: {row.service}. This exposes sensitive data to the internet."
                    affected_assets = [row.asset.value]
                    references = [get_external_reference(title, risk), "https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html"]
                    recommendations = [
                        "1. Restrict database access to trusted IPs/networks only using firewall rules.",
                        "2. Disable remote access unless strictly necessary.",
                        "3. Enforce strong authentication and encryption for all database connections.",
                        "4. Regularly audit firewall and security group rules for database servers.",
                        "5. Monitor for unauthorized access attempts and review logs routinely.",
                        "6. Remove default accounts and change default passwords.",
                    ]
                    cat_findings.append({
                        "title": title,
                        "risk": risk,
                        "affected_assets": affected_assets,
                        "recommendations": recommendations,
                        "references": references,
                    })
                # Exposed RDP/SSH
                elif hasattr(row, 'service') and (row.service and ("rdp" in row.service.lower() or "ssh" in row.service.lower())):
                    title = f"Exposed {row.service.upper()} Service on {row.asset.value}"
                    risk = f"Publicly accessible {row.service.upper()} service detected. This increases risk of brute-force and unauthorized access."
                    affected_assets = [row.asset.value]
                    references = [get_external_reference(title, risk), "https://csrc.nist.gov/publications/detail/sp/800-153/final"]
                    recommendations = [
                        "1. Restrict RDP/SSH access to trusted IPs via firewall rules.",
                        "2. Disable password authentication; use key-based authentication for SSH.",
                        "3. Change default ports if possible to reduce automated attacks.",
                        "4. Enable multi-factor authentication (MFA) for all remote access.",
                        "5. Monitor and log all access attempts and review regularly.",
                    ]
                    cat_findings.append({
                        "title": title,
                        "risk": risk,
                        "affected_assets": affected_assets,
                        "recommendations": recommendations,
                        "references": references,
                    })
                # Cookie Security
                elif hasattr(row, 'header') and (row.header or '').lower() == 'set-cookie':
                    title = f"Cookie Security Issue on {row.asset.value}"
                    risk = f"Cookie missing Secure, HttpOnly, or SameSite flags. This increases risk of session hijacking or CSRF."
                    affected_assets = [row.asset.value]
                    references = [get_external_reference(title, risk), "https://cheatsheetseries.owasp.org/cheatsheets/Cookie_Security_Cheat_Sheet.html"]
                    recommendations = [
                        "1. Set the Secure flag to ensure cookies are sent over HTTPS only.",
                        "2. Set the HttpOnly flag to prevent JavaScript access to cookies.",
                        "3. Set SameSite=Strict or Lax to prevent CSRF attacks.",
                        "4. Regularly review cookie scope and necessity; remove unnecessary cookies.",
                    ]
                    cat_findings.append({
                        "title": title,
                        "risk": risk,
                        "affected_assets": affected_assets,
                        "recommendations": recommendations,
                        "references": references,
                    })
                # Patch Management (Unpatched CVEs)
                elif hasattr(row, 'cve_id') or (hasattr(row, 'finding') and 'cve' in (row.finding or '').lower()):
                    title = f"Unpatched Vulnerability: {getattr(row, 'cve_id', 'CVE') or 'CVE'}"
                    risk = f"Unpatched vulnerability detected. Attackers may exploit this to compromise the system."
                    affected_assets = [row.asset.value] if hasattr(row, 'asset') else []
                    references = [get_external_reference(title, risk), "https://csrc.nist.gov/publications/detail/sp/800-40/rev-3/final"]
                    recommendations = [
                        "1. Maintain an up-to-date inventory of all assets and software.",
                        "2. Subscribe to vendor and security mailing lists for CVE alerts.",
                        "3. Prioritize patching based on CVSS score and exploitability.",
                        "4. Test patches in a staging environment before production deployment.",
                        "5. Document and verify patch application for audit purposes.",
                    ]
                    cat_findings.append({
                        "title": title,
                        "risk": risk,
                        "affected_assets": affected_assets,
                        "recommendations": recommendations,
                        "references": references,
                    })
                # Other Findings
                elif hasattr(row, 'title') and hasattr(row, 'evidence'):
                    title = row.title
                    risk = row.evidence or "Security finding."
                    affected_assets = [row.asset.value] if hasattr(row, 'asset') else []
                    references = [get_external_reference(title, risk)]
                    recommendations = [
                        "1. Review the finding in detail and assess its impact on your environment.",
                        "2. Apply remediation steps as recommended by OWASP Top Ten or relevant security standards.",
                        "3. Document the remediation and verify closure with a follow-up scan.",
                    ]
                    cat_findings.append({
                        "title": title,
                        "risk": risk,
                        "affected_assets": affected_assets,
                        "recommendations": recommendations,
                        "references": references,
                    })
            if cat_findings:
                grouped_findings[cat] = cat_findings

        # Generate DOCX in memory
        output = generate_detailed_report_docx(report_title, executive_summary, grouped_findings, organization_name=organization_name)
        filename = f"detailed_report_scan_{scan_id}.docx"
        return FileResponse(output, as_attachment=True, filename=filename, content_type='application/vnd.openxmlformats-officedocument.wordprocessingml.document')
