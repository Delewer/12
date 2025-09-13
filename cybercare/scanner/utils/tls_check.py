import ssl, socket, datetime

def check_tls(host: str, port: int = 443) -> dict:
    res = {
        "reachable": False,
        "cert_valid": False,
        "days_left": None,
        "min_tls_version": None,  # ex: "TLS1.0 enabled" / "TLS1.2 only"
    }
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=2.5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                res["reachable"] = True
                cert = ssock.getpeercert()
                if cert:
                    # exp date
                    exp_str = cert.get("notAfter")
                    if exp_str:
                        exp = datetime.datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z")
                        res["days_left"] = (exp - datetime.datetime.utcnow()).days
                        res["cert_valid"] = res["days_left"] > 0

                # versiune negociată (nu "minim acceptat", dar util)
                res["negotiated_tls_version"] = ssock.version()

        # Heuristic pentru versiuni vechi încă active: încercăm explicit 1.0/1.1/1.2.
        legacy_enabled = []
        for proto, label in [
            (ssl.PROTOCOL_TLSv1, "TLS1.0"),
            (ssl.PROTOCOL_TLSv1_1, "TLS1.1"),
            (ssl.PROTOCOL_TLSv1_2, "TLS1.2"),
        ]:
            try:
                ctx2 = ssl.SSLContext(proto)
                ctx2.set_ciphers("DEFAULT")
                with socket.create_connection((host, port), timeout=2.5) as s2:
                    with ctx2.wrap_socket(s2, server_hostname=host):
                        legacy_enabled.append(label)
            except Exception:
                pass
        if legacy_enabled:
            res["min_tls_version"] = ", ".join(sorted(set(legacy_enabled)))
        else:
            res["min_tls_version"] = "TLS1.3 only (probabil)"
    except Exception:
        pass
    return res
