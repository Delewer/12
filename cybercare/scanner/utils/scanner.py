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


def domain_exists(domain: str) -> bool:
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False


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


def mini_scan(domain: str) -> dict:
    """Мини-скан субдомена: открытые порты + TLS."""
    result = {
        "target": domain,
        "ports": [],  # список номеров открытых портов
        "tls": {"valid": False, "version": None, "days_left": None},
    }

    for port in [80, 443, 21, 22, 25]:
        try:
            sock = socket.create_connection((domain, port), timeout=2)
            result["ports"].append(port)
            sock.close()

            if port == 443:
                ctx = ssl.create_default_context()
                with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                    s.settimeout(3)
                    s.connect((domain, 443))
                    cert = s.getpeercert()
                    result["tls"]["valid"] = True
                    result["tls"]["version"] = s.version()
        except Exception:
            continue

    return result



def perform_scan(domain: str) -> dict:
    """Полный скан основного домена + субдоменов."""
    if not domain_exists(domain):
        return {"error": f"Domeniul {domain} nu există sau nu răspunde."}

    # Основной домен
    subs = find_subdomains(domain)
    sub_scans = [mini_scan(s) for s in subs]

    return {
        "target": domain,
        "subdomains": subs,
        "subdomain_scans": sub_scans,
    }
