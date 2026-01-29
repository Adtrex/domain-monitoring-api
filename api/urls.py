from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views
from .views import nuclei_scan

router = DefaultRouter()

app_name = 'api'

urlpatterns = [
    path('', include(router.urls)),
    path('test/', views.test_endpoint, name='test'),
    path('scan/', nuclei_scan, name='nuclei_scan'),
]