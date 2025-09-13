import socket
from typing import Dict, List

# Portscan "safe & light" – câteva porturi uzuale (poți extinde)
COMMON_PORTS = [
    21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
    8080, 8443, 3389, 3306, 5432, 27017
]

def run_port_scan(host: str, timeout: float = 0.8) -> Dict:
    open_ports: List[int] = []
    for p in COMMON_PORTS:
        try:
            with socket.create_connection((host, p), timeout=timeout):
                open_ports.append(p)
        except Exception:
            pass

    services = []
    for p in open_ports:
        services.append(_guess_service(p))

    return {
        "open_ports": open_ports,
        "services": services,
        "notes": "Scan rapid pe porturi comune. Pentru acoperire extinsă, rulează nmap separat."
    }

def _guess_service(port: int) -> str:
    mapping = {
        21: "FTP",
        22: "SSH",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        465: "SMTPS",
        587: "SMTP (submission)",
        993: "IMAPS",
        995: "POP3S",
        8080: "HTTP-alt",
        8443: "HTTPS-alt",
        3389: "RDP",
        3306: "MySQL",
        5432: "PostgreSQL",
        27017: "MongoDB",
    }
    return mapping.get(port, f"Port {port}")
