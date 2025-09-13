from django.shortcuts import render, redirect, get_object_or_404
from django.utils import timezone
from django.contrib import messages
from .forms import ScanForm
from .models import Target, Scan
from .tasks import run_full_scan
from .utils.domains import domain_exists, find_subdomains
import os
import platform
from django.http import HttpResponse
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from .models import Scan

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

from django.http import JsonResponse, HttpResponse
from django.shortcuts import get_object_or_404
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
import io

from .models import Scan


def export_json(request, scan_id):
    scan = get_object_or_404(Scan, pk=scan_id)
    data = {
        "target": scan.target.input_value,
        "score": scan.score,
        "severity": scan.severity,
        "status": scan.status,
        "started_at": scan.started_at,
        "finished_at": scan.finished_at,
        "ports": scan.ports,
        "tls": scan.tls,
        "headers": scan.headers,
        "email_auth": scan.email_auth,
        "cves": scan.cves,
        "subdomains": scan.subdomains,
        "subdomain_scans": scan.subdomain_scans,
    }
    return JsonResponse(data, json_dumps_params={"indent": 2})


def register_unicode_font():
    """Подключает шрифт в зависимости от ОС"""
    system = platform.system()
    font_path = None

    if system == "Windows":
        font_path = "C:/Windows/Fonts/arial.ttf"
    elif system in ("Linux", "Darwin"):  # Darwin = macOS
        font_path = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"

    if font_path and os.path.exists(font_path):
        pdfmetrics.registerFont(TTFont("UnicodeFont", font_path))
        return "UnicodeFont"

    # fallback на встроенный
    return "Helvetica"


def export_pdf(request, scan_id):
    scan = Scan.objects.get(pk=scan_id)

    response = HttpResponse(content_type="application/pdf")
    response["Content-Disposition"] = f'attachment; filename=\"raport_{scan.target.input_value}.pdf\"'

    doc = SimpleDocTemplate(response)
    styles = getSampleStyleSheet()

    font_path = "C:/Windows/Fonts/arial.ttf" if platform.system() == "Windows" else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
    pdfmetrics.registerFont(TTFont("ArialUni", font_path))
    normal = ParagraphStyle("normal", parent=styles["Normal"], fontName="ArialUni", fontSize=10, leading=14)
    title = ParagraphStyle("title", parent=styles["Heading1"], fontName="ArialUni", fontSize=14, alignment=1)

    content = []

    # Titlu
    content.append(Paragraph(f"Raport de conformitate CyberCare – {scan.target.input_value}", title))
    content.append(Spacer(1, 14))

    # 1. Informații generale
    content.append(Paragraph("<b>1. Informații generale</b>", normal))
    content.append(Paragraph("Această secțiune prezintă detaliile de bază ale domeniului verificat.", normal))
    content.append(Paragraph(f"Domeniu / IP verificat: {scan.target.input_value}", normal))
    content.append(Paragraph(f"Data scanării: {scan.started_at.strftime('%d.%m.%Y %H:%M')}", normal))
    content.append(Paragraph("Responsabil scanare: CyberCare (auto-audit)", normal))
    content.append(Spacer(1, 12))

    # 2. Rezumat general
    content.append(Paragraph("<b>2. Rezumat general</b>", normal))
    content.append(Paragraph("Scorul reprezintă nivelul de conformitate tehnică al domeniului.", normal))
    content.append(Paragraph(f"Scor total de conformitate: {scan.score or '—'}%", normal))
    status_map = {"green": "Conform", "yellow": "Parțial conform", "red": "Neconform"}
    content.append(Paragraph(f"Status general: {status_map.get(scan.severity, scan.severity)}", normal))
    content.append(Spacer(1, 12))

    # 3. Rezultatele verificării tehnice
    content.append(Paragraph("<b>3. Rezultatele verificării tehnice</b>", normal))
    content.append(Paragraph("Această secțiune reflectă cerințele minime prevăzute de Legea nr. 48/2023 și HG nr. 49/2025 (Art. 11).", normal))
    
    # Porturi
    ports = ", ".join(scan.ports.get("open_ports", [])) if scan.ports else "—"
    content.append(Paragraph(f"🔹 Porturi deschise: {ports}", normal))

    # TLS
    tls_valid = "Da" if scan.tls.get("valid") else "Nu"
    content.append(Paragraph(f"🔹 Certificat TLS valid: {tls_valid}", normal))
    content.append(Paragraph(f"🔹 Versiuni acceptate: {scan.tls.get('versions', 'necunoscut')}", normal))
    content.append(Paragraph(f"🔹 Expiră în: {scan.tls.get('days_left', 'n/a')} zile", normal))

    # Headers
    content.append(Paragraph(f"🔹 HSTS: {'Da' if scan.headers.get('hsts') else 'Nu'}", normal))
    content.append(Paragraph(f"🔹 CSP: {'Da' if scan.headers.get('csp') else 'Nu'}", normal))
    content.append(Paragraph(f"🔹 X-Frame-Options: {'Da' if scan.headers.get('xfo') else 'Nu'}", normal))

    # Email
    content.append(Paragraph(f"🔹 SPF: {'Da' if scan.email_auth.get('spf') else 'Nu'}", normal))
    content.append(Paragraph(f"🔹 DKIM: {scan.email_auth.get('dkim', 'Nu')}", normal))
    content.append(Paragraph(f"🔹 DMARC: {'Da' if scan.email_auth.get('dmarc') else 'Nu'}", normal))

    # CVE
    cves = ", ".join([c.get("cve_id") for c in scan.cves.get("items", [])]) if scan.cves else "Nicio vulnerabilitate detectată"
    content.append(Paragraph(f"🔹 Vulnerabilități cunoscute (CVE): {cves}", normal))
    content.append(Spacer(1, 12))

    # 4. Subdomenii
    if scan.subdomains:
        content.append(Paragraph("<b>4. Subdomenii identificate</b>", normal))
        content.append(Paragraph("Această secțiune listează subdomeniile care pot expune servicii suplimentare.", normal))
        for sub in scan.subdomains:
            content.append(Paragraph(f"• {sub}", normal))

    # 5. Concluzie
    content.append(Spacer(1, 12))
    content.append(Paragraph("<b>5. Concluzie</b>", normal))
    content.append(Paragraph("Acest raport are caracter informativ și educativ. Pentru conformitate deplină este necesar un audit extern realizat de specialiști acreditați.", normal))

    doc.build(content)
    return response

from .utils.compliance import QUESTIONS

def compliance_list(request):
    return render(request, "scanner/compliance_list.html", {"questions": QUESTIONS})

from django.shortcuts import render
from django.http import JsonResponse, HttpResponse
import json
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from io import BytesIO

def incident_report(request):
    return render(request, "scanner/incident_report.html")

# Export JSON
def export_incident_json(request):
    data = {
        "etapa": request.GET.get("etapa"),
        "tip": request.GET.get("tip"),
        "impact": request.GET.get("impact"),
        "recurent": request.GET.get("recurent"),
    }
    return JsonResponse(data)

# Export PDF
def export_incident_pdf(request):
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=A4)
    p.setFont("Helvetica-Bold", 14)
    p.drawString(100, 800, "Raport incident – CyberCare")
    p.setFont("Helvetica", 12)

    y = 760
    for k, v in request.GET.items():
        p.drawString(80, y, f"{k.capitalize()}: {v}")
        y -= 20

    p.showPage()
    p.save()
    buffer.seek(0)
    return HttpResponse(buffer, content_type="application/pdf")
