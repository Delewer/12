import dns.resolver

COMMON_DKIM_SELECTORS = ["default", "selector1", "selector2", "dkim", "mail", "mx"]

def check_email_auth(domain: str) -> dict:
    out = {"spf": False, "dkim": "unknown", "dmarc": False, "dkim_selectors_found": []}

    # SPF: căutăm TXT cu v=spf1
    try:
        txts = dns.resolver.resolve(domain, "TXT", lifetime=3)
        for r in txts:
            s = b"".join(r.strings).decode("utf-8", errors="ignore")
            if s.lower().startswith("v=spf1"):
                out["spf"] = True
                break
    except Exception:
        pass

    # DMARC: _dmarc.domain TXT
    try:
        dmarc = f"_dmarc.{domain}"
        txts = dns.resolver.resolve(dmarc, "TXT", lifetime=3)
        for r in txts:
            s = b"".join(r.strings).decode("utf-8", errors="ignore")
            if s.lower().startswith("v=dmarc1"):
                out["dmarc"] = True
                break
    except Exception:
        pass

    # DKIM (heuristic): încercăm câțiva selectori comuni
    found_any = False
    for sel in COMMON_DKIM_SELECTORS:
        name = f"{sel}._domainkey.{domain}"
        try:
            txts = dns.resolver.resolve(name, "TXT", lifetime=2)
            for r in txts:
                s = b"".join(r.strings).decode("utf-8", errors="ignore").lower()
                if "v=dkim1" in s and "p=" in s:
                    found_any = True
                    out["dkim_selectors_found"].append(sel)
                    break
        except Exception:
            continue
    if found_any:
        out["dkim"] = "ok"
    elif out["dmarc"] or out["spf"]:
        out["dkim"] = "partial"
    else:
        out["dkim"] = "missing"

    return out
