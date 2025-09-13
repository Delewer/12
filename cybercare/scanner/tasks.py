from celery import shared_task
from django.utils import timezone
from django.conf import settings
from .models import Scan
from .utils.portscan import run_port_scan
from .utils.tls_check import check_tls
from .utils.web_headers import check_web_headers
from .utils.email_auth import check_email_auth
from .utils.cve_lookup import lookup_cves
from .utils.scoring import compute_score, severity_from_score, build_summary

@shared_task
def run_full_scan(scan_id: int):
    scan = Scan.objects.get(pk=scan_id)
    scan.status = "running"
    scan.save(update_fields=["status"])

    target = scan.target.input_value

    try:
        ports = run_port_scan(target)                         # dict
        tls  = check_tls(target)                              # dict
        headers = check_web_headers(target)                   # dict
        email = check_email_auth(target)                      # dict
        cves  = lookup_cves(headers, tls)                     # dict (heuristic din Server/tech versiune)
        score = compute_score(ports, tls, headers, email, cves)
        sev = severity_from_score(score)
        summary = build_summary(target, score, sev, ports, tls, headers, email, cves)

        scan.ports = ports
        scan.tls = tls
        scan.headers = headers
        scan.email_auth = email
        scan.cves = cves
        scan.score = score
        scan.severity = sev
        scan.summary = summary
        scan.status = "done"
        scan.finished_at = timezone.now()
        scan.save()
    except Exception as e:
        scan.status = "error"
        scan.summary = f"Eroare în timpul scanării: {e}"
        scan.finished_at = timezone.now()
        scan.save()
