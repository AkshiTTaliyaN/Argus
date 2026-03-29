# 👁 Argus — Network & Web Security Auditor

> *In Greek mythology, Argus Panoptes was a giant with a hundred eyes — all-seeing, nothing escaped his watch.*  
> This tool embodies that: auditing every layer of a domain's security in one scan.

![Python](https://img.shields.io/badge/Python-3.9+-00ff9f?style=flat-square&logo=python&logoColor=black)
![Streamlit](https://img.shields.io/badge/Streamlit-1.32+-00cfff?style=flat-square&logo=streamlit&logoColor=black)
![License](https://img.shields.io/badge/License-MIT-4a6375?style=flat-square)

---

## 📸 What It Does

Argus audits any domain across **4 independent security modules** running in parallel and produces a weighted risk score mapped to a letter grade (A–F):

| Module | What It Checks |
|---|---|
| ⚡ **Port Scanner** | Open ports via Nmap — flags FTP, Telnet, MySQL, RDP, SSH, SMTP |
| 🌐 **HTTP Headers** | 6 critical security headers, cookie flags (Secure/HttpOnly/SameSite), server fingerprinting |
| 🔒 **SSL / TLS** | Certificate validity, issuer, expiry, self-signed detection, TLS version |
| 📡 **DNS Security** | SPF, DMARC, DKIM records + subdomain enumeration (35+ wordlist) |

Every finding includes a **remediation suggestion** explaining exactly how to fix the issue.

---

## 🚀 Run Locally

### 1. Clone the repository
```bash
git clone https://github.com/AkshitTTaliyaN/argus.git
cd argus
```

### 2. Install system dependency (Nmap)
```bash
# Ubuntu / Debian
sudo apt install nmap

# macOS
brew install nmap
```

### 3. Install Python dependencies
```bash
pip install -r requirements.txt
```

### 4. Launch the app
```bash
streamlit run app.py
```

Open [http://localhost:8501](http://localhost:8501) in your browser.

---

## ☁️ Deploy on Streamlit Cloud

1. Push this repository to GitHub
2. Go to [share.streamlit.io](https://share.streamlit.io) → **New app**
3. Select your repo, set **Main file path** to `app.py`
4. Click **Deploy**

> Streamlit Cloud reads `packages.txt` automatically to install Nmap at the system level.

---

## 🗂️ Project Structure

```
argus/
├── app.py                  # Main Streamlit application
├── requirements.txt        # Python dependencies
├── packages.txt            # System packages (Nmap) for Streamlit Cloud
├── README.md
└── modules/
    ├── __init__.py
    ├── scanner.py          # Nmap port scanner
    ├── web_audit.py        # HTTP header & cookie auditor
    ├── ssl_checker.py      # SSL/TLS certificate inspector
    ├── dns_checker.py      # DNS: SPF, DMARC, DKIM, subdomain enumeration
    └── scorer.py           # Risk aggregator & grade calculator
```

---

## 🧮 Risk Scoring System

| Score | Grade | Meaning |
|---|---|---|
| 0 | **A** | Excellent — No issues found |
| 1–20 | **B** | Good — Minor issues |
| 21–40 | **C** | Fair — Needs attention |
| 41–70 | **D** | Poor — Serious vulnerabilities |
| 71+ | **F** | Critical — Immediate action required |

Each category (Network, Web, SSL, DNS) also gets an individual grade visible in the dashboard.

---

## 🛡️ Security Best Practices Applied

- **Input sanitisation** — strips `http://`, `https://`, trailing slashes before processing
- **No hardcoded credentials** — zero secrets in source code (OWASP)
- **Principle of least privilege** — each module has a single responsibility
- **Graceful error handling** — all modules wrapped in try/except, no stack trace leakage
- **HTTPS-first** — attempts HTTPS before falling back to HTTP, penalises HTTP-only sites
- **Ethical scanning** — passive reconnaissance only (`--open`, focused port list, `-T4` timing)
- **Separation of concerns** — detection, analysis, scoring, and presentation fully decoupled

---

## ⚠️ Legal Notice

Argus is designed for **passive, non-destructive reconnaissance only**.  
Only scan domains you own or have explicit written permission to audit.  
Unauthorised scanning may violate computer misuse laws in your jurisdiction.

---

## 👤 Author

**Akshit** — B.Tech Computer Science, Amity University Noida  
GitHub: [@AkshitTTaliyaN](https://github.com/AkshitTTaliyaN)

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
