from django.shortcuts import render, redirect, get_object_or_404
from django.utils import timezone
from django.contrib import messages
from .forms import ScanForm
from .models import Target, Scan
from .tasks import run_full_scan
from .utils.domains import domain_exists, find_subdomains
  # ✅ импорт работает

def dashboard(request):
    form = ScanForm()
    scans = Scan.objects.select_related("target").order_by("-started_at")[:20]
    return render(request, "scanner/dashboard.html", {"form": form, "scans": scans})


from .utils.domains import perform_scan

def start_scan(request):
    if request.method == "POST":
        form = ScanForm(request.POST)
        if form.is_valid():
            input_value = form.cleaned_data["target"].strip()

            result = perform_scan(input_value)

            if "error" in result:
                messages.error(request, result["error"])
                return redirect("dashboard")

            target = Target.objects.create(input_value=input_value)
            scan = Scan.objects.create(
            target=target,
            status="done",
            started_at=timezone.now(),
            ports=result["ports"],
            tls=result["tls"],
            headers=result["headers"],
            subdomains=result["subdomains"],
            subdomain_scans=result["subdomain_scans"],
            score=result["score"],
            severity=result["severity"],
            summary="Basic scan finished",
            )
            scan.subdomains = result["subdomains"]
            scan.save()

            return redirect("scan_detail", scan_id=scan.id)
    return redirect("dashboard")


def scan_detail(request, scan_id):
    scan = get_object_or_404(Scan, pk=scan_id)
    return render(request, "scanner/scan_detail.html", {"scan": scan})


def landing(request):
    return render(request, "scanner/landing.html")
