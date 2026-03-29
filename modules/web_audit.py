"""
web_audit.py — HTTP security header & cookie auditor
"""
import requests

SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "abbr": "CSP",
        "description": "Whitelists trusted sources of scripts, images, and iframes.",
        "attack": "Cross-Site Scripting (XSS)",
        "fix": "Add 'Content-Security-Policy: default-src \\'self\\'' to your server response headers."
    },
    "Strict-Transport-Security": {
        "abbr": "HSTS",
        "description": "Forces browser to always use HTTPS, even if user types http://.",
        "attack": "SSL Stripping / Man-in-the-Middle",
        "fix": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'."
    },
    "X-Frame-Options": {
        "abbr": "XFO",
        "description": "Prevents this page from being loaded inside an iframe on another site.",
        "attack": "Clickjacking",
        "fix": "Add 'X-Frame-Options: SAMEORIGIN' to your server response headers."
    },
    "X-Content-Type-Options": {
        "abbr": "XCTO",
        "description": "Prevents browser from guessing content type (MIME sniffing).",
        "attack": "MIME Sniffing Attacks",
        "fix": "Add 'X-Content-Type-Options: nosniff' to your server response headers."
    },
    "Referrer-Policy": {
        "abbr": "RP",
        "description": "Controls how much referrer info is shared with other sites.",
        "attack": "Sensitive URL Leakage",
        "fix": "Add 'Referrer-Policy: strict-origin-when-cross-origin' to your response headers."
    },
    "Permissions-Policy": {
        "abbr": "PP",
        "description": "Controls which browser APIs (camera, mic, geolocation) the page can access.",
        "attack": "Silent Hardware Hijacking",
        "fix": "Add 'Permissions-Policy: camera=(), microphone=(), geolocation=()' to response headers."
    },
}

HEADERS_RISK_SCORE = 10  # per missing header


def audit(domain: str) -> dict:
    """
    Audits HTTP security headers and cookies for a domain.
    Returns dict: https, url, headers, cookies, risk_score, error.
    """
    result = {
        "https": False,
        "url": "",
        "headers_present": [],
        "headers_missing": [],
        "cookies": [],
        "risk_score": 0,
        "raw_headers": {},
        "server": "",
        "x_powered_by": "",
        "error": None
    }

    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Argus Security Auditor)"
    })

    # Try HTTPS first, fall back to HTTP
    for scheme in ["https", "http"]:
        url = f"{scheme}://{domain}"
        try:
            resp = session.get(url, timeout=10, allow_redirects=True, verify=True)
            result["url"] = resp.url
            result["https"] = resp.url.startswith("https://")
            result["raw_headers"] = dict(resp.headers)
            result["server"] = resp.headers.get("Server", "")
            result["x_powered_by"] = resp.headers.get("X-Powered-By", "")

            if not result["https"]:
                result["risk_score"] += 20  # no HTTPS at all

            # --- Check security headers ---
            for header, meta in SECURITY_HEADERS.items():
                found = any(k.lower() == header.lower() for k in resp.headers)
                entry = {**meta, "header": header, "present": found}
                if found:
                    result["headers_present"].append(entry)
                else:
                    result["headers_missing"].append(entry)
                    result["risk_score"] += HEADERS_RISK_SCORE

            # --- Check cookies ---
            for cookie in resp.cookies:
                cookie_info = {
                    "name": cookie.name,
                    "secure": cookie.secure,
                    "httponly": cookie.has_nonstandard_attr("HttpOnly") or cookie.has_nonstandard_attr("httponly"),
                    "samesite": cookie.get_nonstandard_attr("SameSite") or cookie.get_nonstandard_attr("samesite") or "",
                    "issues": []
                }

                if not cookie_info["secure"]:
                    cookie_info["issues"].append({
                        "flag": "Secure",
                        "reason": "Cookie sent over unencrypted HTTP connections.",
                        "fix": "Add the 'Secure' attribute to this cookie."
                    })
                    result["risk_score"] += 10

                if not cookie_info["httponly"]:
                    cookie_info["issues"].append({
                        "flag": "HttpOnly",
                        "reason": "Cookie accessible via JavaScript — vulnerable to XSS theft.",
                        "fix": "Add the 'HttpOnly' attribute to this cookie."
                    })
                    result["risk_score"] += 5

                if not cookie_info["samesite"]:
                    cookie_info["issues"].append({
                        "flag": "SameSite",
                        "reason": "No SameSite attribute — vulnerable to CSRF attacks.",
                        "fix": "Add 'SameSite=Strict' or 'SameSite=Lax' to this cookie."
                    })
                    result["risk_score"] += 5

                result["cookies"].append(cookie_info)

            return result  # success — stop trying schemes

        except requests.exceptions.SSLError:
            if scheme == "https":
                continue  # try HTTP
            result["error"] = "SSL handshake failed on both HTTPS and HTTP."
        except requests.exceptions.ConnectionError:
            if scheme == "https":
                continue
            result["error"] = f"Could not connect to {domain}. Host may be unreachable."
        except requests.exceptions.Timeout:
            result["error"] = f"Request to {domain} timed out after 10 seconds."
            return result
        except Exception as e:
            result["error"] = f"Web audit failed: {str(e)}"
            return result

    return result
