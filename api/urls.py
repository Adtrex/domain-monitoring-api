from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views


# Create router for viewsets
router = DefaultRouter()
router.register(r'domains', views.DomainViewSet, basename='domain')  # ADD THIS
router.register(r'assets', views.AssetViewSet, basename='asset')      # ADD THIS
router.register(r'scans', views.ScanViewSet, basename='scan')

urlpatterns = [
    # Router URLs (viewset endpoints)
    path('', include(router.urls)),
    
    # Scan-specific check endpoints (separate to avoid timeouts)
    path('scans/<int:scan_id>/library-checks/', 
         views.scan_library_checks, 
         name='scan-library-checks'),
    
    path('scans/<int:scan_id>/ssl-checks/', 
         views.scan_ssl_checks, 
         name='scan-ssl-checks'),
    
    path('scans/<int:scan_id>/email-checks/', 
         views.scan_email_checks, 
         name='scan-email-checks'),
    
    path('scans/<int:scan_id>/header-checks/', 
         views.scan_header_checks, 
         name='scan-header-checks'),
    
    path('scans/<int:scan_id>/dns-checks/', 
         views.scan_dns_checks, 
         name='scan-dns-checks'),
    
    path('scans/<int:scan_id>/findings/', 
         views.scan_findings, 
         name='scan-findings'),
    
    # Nuclei scan execution
    path('nuclei/scan/', 
         views.execute_nuclei_scan, 
         name='nuclei-scan'),
    
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
]