def compute_score(ports, tls, headers, email, cves) -> int:
    # Bază 100p, scădem pe riscuri (MVP simplu dar explicabil)
    score = 100

    # Porturi
    risky = {21, 23, 3389}
    open_ports = set(ports.get("open_ports", []))
    score -= min(20, 3 * len(open_ports & risky))
    score -= min(10, max(0, len(open_ports) - 2))  # multe porturi scad scorul

    # TLS
    if not tls.get("reachable"):
        score -= 5
    if not tls.get("cert_valid"):
        score -= 10
    minv = (tls.get("min_tls_version") or "").lower()
    if "tls1.0" in minv or "tls1.1" in minv:
        score -= 15

    # Headers
    if not headers.get("hsts"):
        score -= 8
    if not headers.get("csp"):
        score -= 10
    if not headers.get("xfo"):
        score -= 5

    # Email
    if not email.get("spf"):
        score -= 8
    dkim = email.get("dkim")
    if dkim in ("missing", "partial"):
        score -= 6 if dkim == "partial" else 10
    if not email.get("dmarc"):
        score -= 12

    # CVE
    cve_items = cves.get("items") or []
    # penalizare ușoară pe CVE-urile critice/High
    high_cnt = sum(1 for i in cve_items if (i.get("severity") or "").upper() in ("CRITICAL", "HIGH"))
    med_cnt = sum(1 for i in cve_items if (i.get("severity") or "").upper() == "MEDIUM")
    score -= min(20, 6 * high_cnt + 3 * med_cnt)

    return max(0, min(100, score))

def severity_from_score(score: int) -> str:
    if score >= 80:
        return "green"
    if score >= 60:
        return "yellow"
    return "red"

def build_summary(target, score, sev, ports, tls, headers, email, cves) -> str:
    dot = "🟢" if sev == "green" else ("🟠" if sev == "yellow" else "🔴")
    return (
        f"Raport de Audit CyberCare – Domeniu/IP: {target}\n"
        f"Scor de conformitate: {dot} {score}%\n"
        f"Disclaimer: Verifică doar partea vizibilă pe internet, nu procesele interne."
    )
