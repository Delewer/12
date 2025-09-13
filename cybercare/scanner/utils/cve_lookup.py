import os, re, requests

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY")

# Extragem versiuni din "Server" header sau TLS notes
VERSION_PATTERNS = [
    (r"apache\/([\d\.]+)", "Apache HTTP Server"),
    (r"nginx\/([\d\.]+)", "nginx"),
    (r"openssh_([\d\.p]+)", "OpenSSH"),
]

def _nvd_headers():
    h = {"User-Agent": "CyberCare-MiniAudit/1.0"}
    if NVD_API_KEY:
        h["apiKey"] = NVD_API_KEY
    return h

def lookup_cves(headers: dict, tls: dict) -> dict:
    server = headers.get("server") or ""
    detected = []
    for pat, product in VERSION_PATTERNS:
        m = re.search(pat, server.lower())
        if m:
            detected.append((product, m.group(1)))

    items = []
    for product, version in detected:
        try:
            # căutare simplă (FREETEXT). Pentru CPE matching e mai complex, dar MVP merge.
            q = f"{product} {version}"
            resp = requests.get(NVD_API, params={"keywordSearch": q, "resultsPerPage": 5},
                                headers=_nvd_headers(), timeout=6)
            data = resp.json()
            for c in data.get("vulnerabilities", []):
                cve = c.get("cve", {})
                cve_id = cve.get("id")
                severity = None
                metrics = cve.get("metrics", {})
                for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if key in metrics and metrics[key]:
                        severity = metrics[key][0]["cvssData"]["baseSeverity"]
                        break
                url = f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else None
                if cve_id:
                    items.append({"cve_id": cve_id, "severity": severity, "url": url})
        except Exception:
            continue

    product_str = ", ".join([f"{p} {v}" for p, v in detected]) if detected else None
    return {"product": product_str, "items": items[:10]}
