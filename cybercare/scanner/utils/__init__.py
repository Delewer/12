from .portscan import run_port_scan
from .tls_check import check_tls
from .web_headers import check_web_headers
from .email_auth import check_email_auth
from .cve_lookup import lookup_cves
from .scoring import compute_score, severity_from_score, build_summary


def perform_scan(target: str) -> dict:
    results = {}
    results["ports"] = run_port_scan(target)
    results["tls"] = check_tls(target)
    results["headers"] = check_web_headers(target)
    results["email_auth"] = check_email_auth(target)
    results["cves"] = lookup_cves(results)

    score = compute_score(results["ports"], results["tls"], results["headers"], results["email_auth"], results["cves"])
    severity = severity_from_score(score)
    summary = build_summary(target, score, severity, results["ports"], results["tls"], results["headers"], results["email_auth"], results["cves"])

    results["score"] = score
    results["severity"] = severity
    results["summary"] = summary

    return results
