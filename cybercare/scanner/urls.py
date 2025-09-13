from django.urls import path
from . import views

urlpatterns = [
    path("", views.landing, name="landing"),              # теперь главная
    path("dashboard/", views.dashboard, name="dashboard"),
    path("scan/<int:scan_id>/", views.scan_detail, name="scan_detail"),
    path("scan/start/", views.start_scan, name="start_scan"),
    path("scan/<int:scan_id>/export/json/", views.export_json, name="export_json"),
    path("scan/<int:scan_id>/export/pdf/", views.export_pdf, name="export_pdf"),
]
