"""
URL configuration for domainscan project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/6.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from api import views as api_views

urlpatterns = [
    path('admin/', admin.site.urls),
    # Explicit report download aliases to avoid URL routing conflicts.
    path('api/report/download/<int:scan_id>/', api_views.scan_report_download, name='api-report-download'),
    path('api/scans/<int:scan_id>/report/download/', api_views.scan_report_download, name='api-scan-report-download'),
    path('api/', include('api.urls')),
]