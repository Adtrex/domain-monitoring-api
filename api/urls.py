from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views
from .report_summary_views import ReportSummaryExportView
from .detailed_report_api import DetailedReportExportView


# Create router for viewsets
router = DefaultRouter()
router.register(r'domains', views.DomainViewSet, basename='domain')  # ADD THIS
router.register(r'assets', views.AssetViewSet, basename='asset')      # ADD THIS
router.register(r'scans', views.ScanViewSet, basename='scan')

urlpatterns = [
     # Report summary export endpoint (domain/asset scoped)
     path('report/summary/export/', ReportSummaryExportView.as_view(), name='report-summary-export'),
     path('report/summary/export/<int:scan_id>/', ReportSummaryExportView.as_view(), name='report-summary-export-scan'),
     path('report/summary/export/<int:scan_id>/<str:report_format>/', ReportSummaryExportView.as_view(), name='report-summary-export-scan-format'),
     path('report/summary/export/<int:scan_id>/<str:report_format>/<int:asset_id>/', ReportSummaryExportView.as_view(), name='report-summary-export-scan-format-asset'),
     # Route sanity-check endpoint for report download troubleshooting
     path(
          'report/download-test/',
          views.report_download_test,
          name='report-download-test-endpoint',
     ),
     path(
          'report/download-debug/<int:scan_id>/',
          views.report_download_debug,
          name='report-download-debug-endpoint',
     ),
     path(
          'report/download-debug/<int:scan_id>/<str:report_format>/',
          views.report_download_debug,
          name='report-download-debug-endpoint-format',
     ),

     # Direct report download route (avoids any scan router path conflicts)
     path(
           'report/download/<int:scan_id>/',
           views.scan_report_download,
           name='report-download',
     ),
     path(
           'report/download/<int:scan_id>/<str:report_format>/',
           views.scan_report_download,
           name='report-download-format',
     ),
          path(
               'report/download/<int:scan_id>/<str:report_format>/<str:domain_name>/',
               views.scan_report_download,
               name='report-download-format-domain',
          ),

    # Router URLs (viewset endpoints)
    path('', include(router.urls)),

     # Explicit report download route
         path(
              'scans/<int:scan_id>/report/download/',
              views.scan_report_download,
              name='scan-report-download',
         ),
         path(
              'scans/<int:scan_id>/report/download/<str:report_format>/',
              views.scan_report_download,
              name='scan-report-download-format',
         ),
         path(
              'scans/<int:scan_id>/report/download/<str:report_format>/<str:domain_name>/',
              views.scan_report_download,
              name='scan-report-download-format-domain',
         ),
    
    # Scan-specific check endpoints (separate to avoid timeouts)
    path('scans/<int:scan_id>/library-checks/', 
         views.scan_library_checks, 
         name='scan-library-checks'),

    path('scans/<int:scan_id>/library-scorecard/',
         views.scan_library_scorecard,
         name='scan-library-scorecard'),
    
    path('scans/<int:scan_id>/ssl-checks/', 
         views.scan_ssl_checks, 
         name='scan-ssl-checks'),

    path('scans/<int:scan_id>/ssl-scorecard/',
         views.scan_ssl_scorecard,
         name='scan-ssl-scorecard'),
    
    path('scans/<int:scan_id>/email-checks/', 
         views.scan_email_checks, 
         name='scan-email-checks'),

    path('scans/<int:scan_id>/email-scorecard/',
         views.scan_email_scorecard,
         name='scan-email-scorecard'),
    
    path('scans/<int:scan_id>/header-checks/', 
         views.scan_header_checks, 
         name='scan-header-checks'),

    path('scans/<int:scan_id>/header-scorecard/',
         views.scan_header_scorecard,
         name='scan-header-scorecard'),
    
    path('scans/<int:scan_id>/dns-checks/', 
         views.scan_dns_checks, 
         name='scan-dns-checks'),

    path('scans/<int:scan_id>/dns-scorecard/',
         views.scan_dns_scorecard,
         name='scan-dns-scorecard'),

    path('scans/<int:scan_id>/overall-scorecard/',
         views.scan_overall_scorecard,
         name='scan-overall-scorecard'),
    
    path('scans/<int:scan_id>/findings/', 
         views.scan_findings, 
         name='scan-findings'),
    
    # Nuclei scan execution
    path('nuclei/scan/', 
         views.execute_nuclei_scan, 
         name='nuclei-scan'),

    # One-call domain scan execution (auto-loads all domain assets)
    path('domains/<int:domain_id>/scan/',
         views.execute_domain_scan,
         name='domain-scan'),
    
    # Dashboard
    path('dashboard/metrics/', 
         views.dashboard_metrics, 
         name='dashboard-metrics'),

    # Findings endpoints
    path('scans/<int:scan_id>/findings/', views.scan_findings, name='scan_findings'),
    path('findings/', views.all_findings, name='all_findings'),  # NEW
    
    # Debug endpoint
    path('debug/scan/<int:scan_id>/', views.debug_scan_data, name='debug_scan_data'),  # NEW

    path('dashboard/executive/', views.executive_dashboard, name='executive-dashboard'),
    path('report/detailed/<int:scan_id>/', DetailedReportExportView.as_view(), name='detailed-report'),
    path('report/detailed/<int:scan_id>/docx/', DetailedReportExportView.as_view(), name='detailed-report-export'),
]