from django.shortcuts import render, redirect, get_object_or_404
from django.utils import timezone
from .forms import ScanForm
from .models import Target, Scan
from .tasks import run_full_scan  # Celery task (poți apela direct pentru sync)

def dashboard(request):
    form = ScanForm()
    scans = Scan.objects.select_related("target").order_by("-started_at")[:20]
    return render(request, "scanner/dashboard.html", {"form": form, "scans": scans})

def start_scan(request):
    if request.method == "POST":
        form = ScanForm(request.POST)
        if form.is_valid():
            input_value = form.cleaned_data["target"].strip()
            target = Target.objects.create(input_value=input_value)
            scan = Scan.objects.create(target=target, status="queued", started_at=timezone.now())
            # Dacă vrei sync (fără Celery), apelează direct: run_full_scan(scan.id)
            run_full_scan(scan.id)  # în background cu Celery
            return redirect("scan_detail", scan_id=scan.id)
    return redirect("dashboard")

def scan_detail(request, scan_id):
    scan = get_object_or_404(Scan, pk=scan_id)
    return render(request, "scanner/scan_detail.html", {"scan": scan})

def landing(request):
    return render(request, "scanner/landing.html")
