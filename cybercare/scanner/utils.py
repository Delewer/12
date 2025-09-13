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
