"""
dns_checker.py — DNS security auditor (SPF, DMARC, DKIM, subdomain enumeration)
"""
import dns.resolver
import dns.exception

COMMON_DKIM_SELECTORS = ["default", "google", "mail", "smtp", "dkim", "k1", "selector1", "selector2"]

COMMON_SUBDOMAINS = [
    "www", "mail", "webmail", "smtp", "pop", "imap", "ftp",
    "api", "dev", "staging", "test", "admin", "portal", "vpn",
    "remote", "secure", "app", "cdn", "static", "assets",
    "blog", "shop", "store", "support", "help", "status",
    "login", "auth", "dashboard", "panel", "cpanel", "server",
    "ns1", "ns2", "mx", "exchange", "autodiscover"
]


def _resolve(name: str, record_type: str) -> list:
    try:
        answers = dns.resolver.resolve(name, record_type, lifetime=5)
        return [r.to_text() for r in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers,
            dns.exception.Timeout, Exception):
        return []


def check_spf(domain: str) -> dict:
    """Check for SPF record in TXT records."""
    result = {
        "present": False,
        "record": "",
        "valid": False,
        "risk_score": 0,
        "fix": "",
        "issues": []
    }
    records = _resolve(domain, "TXT")
    for r in records:
        clean = r.strip('"')
        if clean.startswith("v=spf1"):
            result["present"] = True
            result["record"] = clean

            if "-all" in clean:
                result["valid"] = True
            elif "~all" in clean:
                result["issues"].append("SPF uses '~all' (softfail) instead of '-all' (hardfail). Spoofed emails may still be delivered.")
                result["fix"] = "Change '~all' to '-all' in your SPF record for strict enforcement."
                result["risk_score"] += 5
            elif "?all" in clean or "+all" in clean:
                result["issues"].append("SPF uses a permissive qualifier — essentially allows anyone to send email as your domain.")
                result["fix"] = "Replace '+all' or '?all' with '-all' in your SPF record immediately."
                result["risk_score"] += 15
            break

    if not result["present"]:
        result["risk_score"] += 15
        result["fix"] = "Add a TXT record: 'v=spf1 include:_spf.yourmailprovider.com -all' to your DNS."
        result["issues"].append("No SPF record found. Anyone can send spoofed emails claiming to be from your domain.")

    return result


def check_dmarc(domain: str) -> dict:
    """Check for DMARC record."""
    result = {
        "present": False,
        "record": "",
        "policy": "",
        "risk_score": 0,
        "fix": "",
        "issues": []
    }
    records = _resolve(f"_dmarc.{domain}", "TXT")
    for r in records:
        clean = r.strip('"')
        if clean.startswith("v=DMARC1"):
            result["present"] = True
            result["record"] = clean

            if "p=reject" in clean:
                result["policy"] = "reject"
            elif "p=quarantine" in clean:
                result["policy"] = "quarantine"
                result["issues"].append("DMARC policy is 'quarantine'. Consider upgrading to 'reject' for full protection.")
                result["fix"] = "Change 'p=quarantine' to 'p=reject' in your DMARC record."
                result["risk_score"] += 5
            elif "p=none" in clean:
                result["policy"] = "none"
                result["issues"].append("DMARC policy is 'none' — monitoring only, no enforcement. Spoofed emails are not blocked.")
                result["fix"] = "Change 'p=none' to 'p=reject' in your DMARC record to enforce protection."
                result["risk_score"] += 10
            break

    if not result["present"]:
        result["risk_score"] += 15
        result["fix"] = "Add a TXT record at '_dmarc.yourdomain.com': 'v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com'"
        result["issues"].append("No DMARC record found. Your domain is unprotected against email spoofing.")

    return result


def check_dkim(domain: str) -> dict:
    """Try common DKIM selectors to detect DKIM configuration."""
    result = {
        "present": False,
        "selector_found": "",
        "record": "",
        "risk_score": 0,
        "fix": "",
        "issues": []
    }
    for selector in COMMON_DKIM_SELECTORS:
        records = _resolve(f"{selector}._domainkey.{domain}", "TXT")
        for r in records:
            clean = r.strip('"')
            if "v=DKIM1" in clean or "p=" in clean:
                result["present"] = True
                result["selector_found"] = selector
                result["record"] = clean[:120] + ("..." if len(clean) > 120 else "")
                return result

    result["risk_score"] += 10
    result["fix"] = "Configure DKIM signing on your mail server and publish the public key as a TXT record at 'selector._domainkey.yourdomain.com'."
    result["issues"].append("No DKIM record found with common selectors. Emails from this domain cannot be cryptographically verified.")
    return result


def enumerate_subdomains(domain: str) -> dict:
    """
    Enumerate subdomains by attempting DNS resolution for common names.
    Returns found subdomains with their IP addresses.
    """
    result = {
        "found": [],
        "count": 0,
        "risk_score": 0,
        "error": None
    }

    HIGH_RISK_SUBDOMAINS = {"dev", "staging", "test", "admin", "panel", "cpanel", "remote", "vpn"}

    for sub in COMMON_SUBDOMAINS:
        fqdn = f"{sub}.{domain}"
        ips = _resolve(fqdn, "A")
        if ips:
            is_risky = sub in HIGH_RISK_SUBDOMAINS
            entry = {
                "subdomain": fqdn,
                "ips": ips,
                "risky": is_risky,
                "reason": f"'{sub}' subdomain exposes internal infrastructure publicly." if is_risky else "",
                "fix": f"Restrict '{fqdn}' behind a VPN or IP allowlist." if is_risky else ""
            }
            result["found"].append(entry)
            if is_risky:
                result["risk_score"] += 10

    result["count"] = len(result["found"])
    return result


def full_dns_check(domain: str) -> dict:
    """Run all DNS checks and return combined results."""
    spf    = check_spf(domain)
    dmarc  = check_dmarc(domain)
    dkim   = check_dkim(domain)
    subs   = enumerate_subdomains(domain)

    total_risk = spf["risk_score"] + dmarc["risk_score"] + dkim["risk_score"] + subs["risk_score"]

    return {
        "spf":        spf,
        "dmarc":      dmarc,
        "dkim":       dkim,
        "subdomains": subs,
        "risk_score": total_risk
    }
