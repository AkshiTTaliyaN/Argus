"""
scanner.py — Network port scanner using python-nmap
"""
import nmap

RISKY_PORTS = {
    21:   {
        "name": "FTP",
        "risk": "critical",
        "reason": "Transmits credentials and data in plaintext. Trivially intercepted by a network sniffer.",
        "fix": "Disable FTP entirely. Use SFTP (port 22) or FTPS instead."
    },
    22:   {
        "name": "SSH",
        "risk": "medium",
        "reason": "Safe when updated. Older OpenSSH versions (e.g. 6.x) have known exploits actively targeted.",
        "fix": "Ensure OpenSSH is up to date. Disable password authentication — use SSH key pairs only."
    },
    23:   {
        "name": "Telnet",
        "risk": "critical",
        "reason": "Predecessor to SSH. Sends everything including passwords in plaintext. Never expose this.",
        "fix": "Disable Telnet immediately. Replace with SSH for all remote access."
    },
    25:   {
        "name": "SMTP",
        "risk": "high",
        "reason": "Exposed SMTP can be abused for spam relaying or email spoofing attacks.",
        "fix": "Restrict SMTP to authenticated users only. Block port 25 externally if not a mail server."
    },
    80:   {
        "name": "HTTP",
        "risk": "medium",
        "reason": "Unencrypted web traffic. Data can be intercepted by a man-in-the-middle attacker.",
        "fix": "Redirect all HTTP traffic to HTTPS using a 301 permanent redirect."
    },
    3306: {
        "name": "MySQL",
        "risk": "critical",
        "reason": "Publicly exposed database port. Allows direct brute-force or SQL injection attacks.",
        "fix": "Bind MySQL to 127.0.0.1 only. Access via SSH tunnel if remote access is needed."
    },
    3389: {
        "name": "RDP",
        "risk": "critical",
        "reason": "Windows Remote Desktop. Frequently targeted by ransomware groups and brute-force attacks.",
        "fix": "Place RDP behind a VPN. Enable Network Level Authentication (NLA) and restrict by IP."
    },
    8080: {
        "name": "HTTP-Alt",
        "risk": "medium",
        "reason": "Common alternative HTTP port. Often runs unencrypted admin panels or dev servers.",
        "fix": "Secure with HTTPS or restrict access to internal networks only."
    },
    8443: {
        "name": "HTTPS-Alt",
        "risk": "low",
        "reason": "Alternative HTTPS port. Check if the service running here is intended to be public.",
        "fix": "Ensure TLS certificates are valid and the service is intended to be publicly accessible."
    },
    443:  {
        "name": "HTTPS",
        "risk": "low",
        "reason": "Standard HTTPS port. Generally safe — ensure TLS is configured correctly.",
        "fix": "Regularly renew SSL certificates and enforce TLS 1.2+ only."
    },
}

SCAN_PORTS = "21,22,23,25,80,443,3306,3389,8080,8443"


def scan(domain: str) -> dict:
    """
    Runs an Nmap port scan on the given domain.
    Returns a dict with open_ports, risky_ports, risk_score, and error.
    """
    result = {
        "open_ports": [],
        "risky_ports": [],
        "risk_score": 0,
        "error": None
    }

    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=domain, arguments=f"-T4 --open -p {SCAN_PORTS}")

        hosts = nm.all_hosts()
        if not hosts:
            result["error"] = "Host unreachable or no open ports found."
            return result

        host = hosts[0]
        if "tcp" not in nm[host]:
            return result

        for port, data in nm[host]["tcp"].items():
            if data["state"] == "open":
                port_info = {
                    "port": port,
                    "name": data.get("name", "unknown"),
                    "product": data.get("product", ""),
                    "version": data.get("version", ""),
                }
                result["open_ports"].append(port_info)

                if port in RISKY_PORTS:
                    risky = RISKY_PORTS[port].copy()
                    risky["port"] = port

                    if risky["risk"] == "critical":
                        if port == 80:
                            result["risk_score"] += 10
                        else:
                            result["risk_score"] += 20
                    elif risky["risk"] == "high":
                        result["risk_score"] += 15
                    elif risky["risk"] == "medium":
                        result["risk_score"] += 10
                    else:
                        result["risk_score"] += 5

                    result["risky_ports"].append(risky)

    except nmap.PortScannerError as e:
        result["error"] = f"Nmap error: {str(e)}. Ensure Nmap is installed (sudo apt install nmap)."
    except Exception as e:
        result["error"] = f"Scan failed: {str(e)}"

    return result
