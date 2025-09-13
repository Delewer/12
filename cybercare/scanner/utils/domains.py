import socket
import ssl
import dns.resolver
import requests
from datetime import datetime

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "api", "dev", "test", "staging",
    "portal", "admin", "app", "blog", "shop", "vpn", "webmail",
    "mx", "ns1", "ns2"
]

COMMON_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306]


# --- Проверка домена ---
def domain_exists(domain: str) -> bool:
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False


# --- Поиск субдоменов ---
def find_subdomains(domain: str) -> list[str]:
    found = []
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 2
    resolver.timeout = 2

    for sub in COMMON_SUBDOMAINS:
        subdomain = f"{sub}.{domain}"
        try:
            answers = resolver.resolve(subdomain, "A")
            if answers:
                found.append(subdomain)
        except Exception:
            continue
    return found


# --- Скан портов ---
def scan_ports(domain: str) -> dict:
    result = {"open": [], "closed": []}
    ip = socket.gethostbyname(domain)

    for port in COMMON_PORTS:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        try:
            s.connect((ip, port))
            result["open"].append(port)
        except Exception:
            result["closed"].append(port)
        finally:
            s.close()
    return result


# --- TLS ---
def check_tls(domain: str) -> dict:
    info = {"valid": False, "issuer": None, "subject": None, "days_left": None}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(3)
            s.connect((domain, 443))
            cert = s.getpeercert()

            info["valid"] = True
            info["issuer"] = dict(x[0] for x in cert["issuer"])
            info["subject"] = dict(x[0] for x in cert["subject"])

            # Дата окончания
            exp_str = cert.get("notAfter")
            if exp_str:
                exp = datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z")
                info["days_left"] = (exp - datetime.utcnow()).days
    except Exception:
        pass
    return info


# --- Заголовки ---
def check_headers(domain: str) -> dict:
    result = {}
    try:
        resp = requests.get(f"https://{domain}", timeout=3, verify=False)
        headers = resp.headers

        result["https"] = resp.url.startswith("https")
        result["csp"] = "Content-Security-Policy" in headers
        result["hsts"] = "Strict-Transport-Security" in headers
        result["xfo"] = "X-Frame-Options" in headers
        result["raw"] = dict(headers)
    except Exception:
        pass
    return result


# --- Примитивный скоринг ---
def calculate_score(ports: dict, tls: dict, headers: dict) -> tuple[int, str]:
    score = 0
    if tls.get("valid"):
        score += 30
    if ports["open"]:
        score += 20
    if headers.get("csp"):
        score += 20
    if headers.get("hsts"):
        score += 20
    if headers.get("xfo"):
        score += 10

    severity = "green" if score > 70 else "yellow" if score > 40 else "red"
    return score, severity


# --- Полный скан ---
def perform_scan(domain: str) -> dict:
    if not domain_exists(domain):
        return {"error": f"Domeniul {domain} nu există sau nu răspunde."}

    ports = scan_ports(domain)
    tls = check_tls(domain)
    headers = check_headers(domain)
    score, severity = calculate_score(ports, tls, headers)

    # ищем субдомены
    subdomains = find_subdomains(domain)
    subdomain_scans = []
    for sub in subdomains:
        ports_s = scan_ports(sub)
        tls_s = check_tls(sub)
        headers_s = check_headers(sub)
        score_s, severity_s = calculate_score(ports_s, tls_s, headers_s)
        subdomain_scans.append({
            "target": sub,
            "ports": ports_s,
            "tls": tls_s,
            "headers": headers_s,
            "score": score_s,
            "severity": severity_s,
        })

    return {
        "target": domain,
        "ports": ports,
        "tls": tls,
        "headers": headers,
        "score": score,
        "severity": severity,
        "subdomains": subdomains,
        "subdomain_scans": subdomain_scans,
    }
