import ssl
import socket
from datetime import datetime, timezone


def check(domain: str) -> dict:
    """
    Connects to domain:443, retrieves and inspects the X.509 certificate.
    Returns dict: valid, issuer, subject, expires, days_left,
                  self_signed, expired, tls_version, risk_score, error.
    """
    result = {
        "valid": False,
        "issuer": "",
        "subject": "",
        "expires": "",
        "days_left": None,
        "self_signed": False,
        "expired": False,
        "tls_version": "",
        "risk_score": 0,
        "error": None
    }

    try:
        context = ssl.create_default_context()
        conn = socket.create_connection((domain, 443), timeout=10)
        tls_conn = context.wrap_socket(conn, server_hostname=domain)

        result["tls_version"] = tls_conn.version()

        cert = tls_conn.getpeercert()
        tls_conn.close()
        conn.close()

        result["valid"] = True

        # --- Subject ---
        subject_dict = dict(x[0] for x in cert.get("subject", []))
        result["subject"] = subject_dict.get("commonName", domain)

        # --- Issuer ---
        issuer_dict = dict(x[0] for x in cert.get("issuer", []))
        issuer_org = issuer_dict.get("organizationName", "")
        issuer_cn  = issuer_dict.get("commonName", "")
        result["issuer"] = issuer_org or issuer_cn or "Unknown"

        # --- Expiry ---
        not_after = cert.get("notAfter", "")
        if not_after:
            expire_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            expire_dt = expire_dt.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            days_left = (expire_dt - now).days
            result["expires"] = expire_dt.strftime("%d %b %Y")
            result["days_left"] = days_left

            if days_left < 0:
                result["expired"] = True
                result["risk_score"] += 40
            elif days_left <= 30:
                result["risk_score"] += 20

        # --- Self-signed check ---
        subject_cn = subject_dict.get("commonName", "")
        issuer_cn2 = issuer_dict.get("commonName", "")
        issuer_o   = issuer_dict.get("organizationName", "")
        if (subject_cn and subject_cn == issuer_cn2) or (issuer_o.lower() in ["", subject_cn.lower()]):
            # Double-check: self-signed if issuer == subject in all fields
            if cert.get("subject") == cert.get("issuer"):
                result["self_signed"] = True
                result["risk_score"] += 30

    except ssl.SSLCertVerificationError as e:
        result["error"] = f"Certificate verification failed: {str(e)}"
        result["risk_score"] += 40

    except ssl.SSLError as e:
        result["error"] = f"SSL error: {str(e)}"
        result["risk_score"] += 30

    except socket.timeout:
        result["error"] = "Connection to port 443 timed out."

    except ConnectionRefusedError:
        result["error"] = "Port 443 is closed — HTTPS not available on this host."
        result["risk_score"] += 20

    except Exception as e:
        result["error"] = f"SSL check failed: {str(e)}"

    return result
