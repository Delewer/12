def perform_scan(domain: str) -> dict:
    """
    Минимальный фейковый сканер.
    Возвращает фиктивный результат, чтобы проверить логику работы.
    """
    return {
        "target": domain,
        "score": 80,
        "severity": "medium",
        "result": {
            "tls": "TLS 1.2",
            "cves": ["CVE-2023-0001", "CVE-2022-0002"],
        },
    }

import socket
import dns.resolver

# 🔹 Список популярных субдоменов
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "api", "dev", "test", "staging",
    "portal", "admin", "app", "blog", "shop", "vpn", "webmail",
    "mx", "ns1", "ns2"
]


# 🔹 Проверка существования домена
def domain_exists(domain: str) -> bool:
    """Проверяет, существует ли домен (резолвится ли в DNS)."""
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False


# 🔹 Поиск популярных субдоменов
def find_subdomains(domain: str) -> list[str]:
    """Ищет базовые субдомены из списка COMMON_SUBDOMAINS."""
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