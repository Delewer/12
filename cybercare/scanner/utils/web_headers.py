import requests

def check_web_headers(host: str) -> dict:
    url = f"https://{host}"
    res = {"https_ok": False, "hsts": False, "csp": False, "xfo": False, "raw": {}}
    try:
        r = requests.get(url, timeout=4, allow_redirects=True)
        res["https_ok"] = r.url.startswith("https://")
        headers = {k.lower(): v for k, v in r.headers.items()}
        res["raw"] = dict(r.headers)

        if "strict-transport-security" in headers:
            res["hsts"] = True
        if "content-security-policy" in headers:
            res["csp"] = True
        if "x-frame-options" in headers:
            res["xfo"] = True

        # Server header (pt CVE heuristic)
        res["server"] = headers.get("server")
    except Exception:
        pass
    return res
