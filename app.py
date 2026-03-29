import streamlit as st
import plotly.graph_objects as go
import threading
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
from modules import scanner, web_audit, ssl_checker, dns_checker, scorer

# ─────────────────────────────────────────────
#  PAGE CONFIG
# ─────────────────────────────────────────────
st.set_page_config(
    page_title="Argus — Security Auditor",
    page_icon="👁",
    layout="wide",
    initial_sidebar_state="collapsed"
)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');

:root {
  --bg:        #0a0d0f;
  --surface:   #0f1419;
  --panel:     #141c24;
  --border:    #1e2d3d;
  --accent:    #00ff9f;
  --accent2:   #00cfff;
  --red:       #ff2244;
  --orange:    #ff8800;
  --yellow:    #ffdd00;
  --green:     #00ff9f;
  --muted:     #4a6375;
  --text:      #c8d8e8;
  --mono:      'Share Tech Mono', monospace;
  --sans:      'Rajdhani', sans-serif;
}

/* Base */
html, body, [data-testid="stAppViewContainer"] {
  background-color: var(--bg) !important;
  color: var(--text) !important;
  font-family: var(--sans) !important;
}

[data-testid="stMain"] { background-color: var(--bg) !important; }
[data-testid="block-container"] { padding: 1.5rem 2.5rem !important; }

/* Hide Streamlit chrome */
#MainMenu, footer, header { visibility: hidden !important; }

/* Headings */
h1,h2,h3,h4 { font-family: var(--sans) !important; color: var(--text) !important; }

/* Input */
[data-testid="stTextInput"] input {
  background: var(--panel) !important;
  border: 1px solid var(--border) !important;
  border-radius: 4px !important;
  color: var(--accent) !important;
  font-family: var(--mono) !important;
  font-size: 1rem !important;
  padding: 0.6rem 1rem !important;
}
[data-testid="stTextInput"] input:focus {
  border-color: var(--accent) !important;
  box-shadow: 0 0 8px rgba(0,255,159,0.25) !important;
  outline: none !important;
}

/* Primary Button */
[data-testid="stButton"] button[kind="primary"] {
  background: transparent !important;
  border: 1.5px solid var(--accent) !important;
  color: var(--accent) !important;
  font-family: var(--mono) !important;
  font-size: 0.95rem !important;
  letter-spacing: 2px !important;
  padding: 0.55rem 2rem !important;
  border-radius: 3px !important;
  transition: all 0.2s !important;
}
[data-testid="stButton"] button[kind="primary"]:hover {
  background: var(--accent) !important;
  color: var(--bg) !important;
  box-shadow: 0 0 18px rgba(0,255,159,0.4) !important;
}

/* Secondary Button */
[data-testid="stButton"] button[kind="secondary"] {
  background: transparent !important;
  border: 1px solid var(--border) !important;
  color: var(--muted) !important;
  font-family: var(--mono) !important;
  font-size: 0.85rem !important;
  border-radius: 3px !important;
}

/* Expander */
[data-testid="stExpander"] {
  background: var(--panel) !important;
  border: 1px solid var(--border) !important;
  border-radius: 6px !important;
  margin-bottom: 0.5rem !important;
}
[data-testid="stExpander"] summary {
  font-family: var(--mono) !important;
  color: var(--text) !important;
  font-size: 0.9rem !important;
}

/* Divider */
hr { border-color: var(--border) !important; margin: 1.2rem 0 !important; }

/* Metric */
[data-testid="stMetric"] { background: var(--panel) !important; border: 1px solid var(--border) !important;
  border-radius: 8px !important; padding: 1rem !important; }
[data-testid="stMetricValue"] { font-family: var(--mono) !important; }

/* Progress */
[data-testid="stProgress"] > div > div { background: var(--accent) !important; }

/* Tabs */
[data-testid="stTabs"] [data-baseweb="tab"] {
  font-family: var(--mono) !important;
  color: var(--muted) !important;
  background: transparent !important;
  border-bottom: 2px solid transparent !important;
}
[data-testid="stTabs"] [data-baseweb="tab"][aria-selected="true"] {
  color: var(--accent) !important;
  border-bottom: 2px solid var(--accent) !important;
}
[data-testid="stTabs"] [data-baseweb="tab-list"] {
  background: var(--panel) !important;
  border-bottom: 1px solid var(--border) !important;
  gap: 0 !important;
}
[data-baseweb="tab-panel"] { background: var(--bg) !important; padding-top: 1.2rem !important; }

/* Alerts */
[data-testid="stAlert"] {
  background: var(--panel) !important;
  border-left: 3px solid var(--accent2) !important;
  border-radius: 4px !important;
  font-family: var(--mono) !important;
  font-size: 0.85rem !important;
}
</style>
""", unsafe_allow_html=True)

def card(content: str, border_color: str = "#1e2d3d") -> str:
    return f"""
    <div style="background:#0f1419;border:1px solid {border_color};border-radius:8px;
                padding:1.2rem 1.4rem;margin-bottom:0.75rem;font-family:'Share Tech Mono',monospace;">
      {content}
    </div>"""


def badge(text: str, color: str) -> str:
    return (f'<span style="background:transparent;border:1px solid {color};color:{color};'
            f'font-family:\'Share Tech Mono\',monospace;font-size:0.75rem;padding:2px 8px;'
            f'border-radius:3px;letter-spacing:1px;">{text}</span>')


def tag(text: str, color: str) -> str:
    bg = color + "22"
    return (f'<span style="background:{bg};color:{color};font-family:\'Share Tech Mono\',monospace;'
            f'font-size:0.75rem;padding:2px 10px;border-radius:12px;">{text.upper()}</span>')


# ─────────────────────────────────────────────
#  RADAR CHART
# ─────────────────────────────────────────────
def render_radar(breakdown: dict):
    categories  = ["Network", "Web Headers", "SSL/TLS", "DNS Security"]
    raw_scores  = [
        breakdown["network"]["score"],
        breakdown["web"]["score"],
        breakdown["ssl"]["score"],
        breakdown["dns"]["score"],
    ]
    # Normalise to 0-100 (higher = worse), invert for visual (higher = safer)
    max_score = 100
    normalised = [min(s / max_score * 100, 100) for s in raw_scores]
    safe_scores = [100 - n for n in normalised]

    fig = go.Figure()
    fig.add_trace(go.Scatterpolar(
        r=safe_scores + [safe_scores[0]],
        theta=categories + [categories[0]],
        fill="toself",
        fillcolor="rgba(0,255,159,0.08)",
        line=dict(color="#00ff9f", width=2),
        name="Security Score"
    ))
    fig.update_layout(
        polar=dict(
            bgcolor="#0f1419",
            radialaxis=dict(
                visible=True, range=[0, 100],
                gridcolor="#1e2d3d", tickfont=dict(color="#4a6375", size=9),
                tickvals=[20, 40, 60, 80, 100]
            ),
            angularaxis=dict(
                gridcolor="#1e2d3d",
                tickfont=dict(color="#c8d8e8", size=12, family="Rajdhani")
            )
        ),
        paper_bgcolor="#0a0d0f",
        plot_bgcolor="#0a0d0f",
        showlegend=False,
        margin=dict(t=30, b=30, l=40, r=40),
        height=320,
    )
    st.plotly_chart(fig, use_container_width=True)


# ─────────────────────────────────────────────
#  SECTION RENDERERS
# ─────────────────────────────────────────────

def render_grade_header(grade_result: dict, domain: str):
    grade   = grade_result["grade"]
    color   = grade_result["color"]
    label   = grade_result["label"]
    total   = grade_result["total_risk"]
    summary = grade_result["summary"]

    st.markdown(f"""
    <div style="background:#0f1419;border:1px solid {color}33;border-radius:12px;
                padding:2rem 2.5rem;margin-bottom:1.5rem;position:relative;overflow:hidden;">
      <div style="position:absolute;top:0;right:0;width:200px;height:200px;
                  background:radial-gradient({color}15, transparent 70%);border-radius:50%;
                  transform:translate(30%,-30%);pointer-events:none;"></div>
      <div style="display:flex;align-items:center;gap:2rem;flex-wrap:wrap;">
        <div style="font-size:5rem;font-weight:700;color:{color};
                    font-family:'Share Tech Mono',monospace;line-height:1;
                    text-shadow:0 0 30px {color}66;">{grade}</div>
        <div>
          <div style="font-size:1.8rem;font-weight:700;color:#c8d8e8;
                      font-family:'Rajdhani',sans-serif;letter-spacing:1px;">{label}</div>
          <div style="font-family:'Share Tech Mono',monospace;color:#4a6375;font-size:0.85rem;
                      margin-top:4px;">{summary}</div>
          <div style="margin-top:0.6rem;font-family:'Share Tech Mono',monospace;font-size:0.8rem;">
            <span style="color:{color};">RISK SCORE</span>
            <span style="color:#c8d8e8;margin-left:10px;">{total} pts</span>
            <span style="color:#4a6375;margin-left:20px;">TARGET →</span>
            <span style="color:#00cfff;margin-left:8px;font-family:'Share Tech Mono',monospace;">{domain}</span>
          </div>
        </div>
      </div>
    </div>
    """, unsafe_allow_html=True)


def render_subscores(breakdown: dict):
    cols = st.columns(4)
    labels = {"network": "NETWORK", "web": "WEB HEADERS", "ssl": "SSL / TLS", "dns": "DNS"}
    icons  = {"network": "⚡", "web": "🌐", "ssl": "🔒", "dns": "📡"}
    for col, (key, label) in zip(cols, labels.items()):
        d = breakdown[key]
        with col:
            st.markdown(f"""
            <div style="background:#0f1419;border:1px solid {d['color']}44;border-radius:8px;
                        padding:1rem;text-align:center;">
              <div style="font-family:'Share Tech Mono',monospace;font-size:0.7rem;
                          color:#4a6375;letter-spacing:2px;">{icons[key]} {label}</div>
              <div style="font-size:2.2rem;font-weight:700;color:{d['color']};
                          font-family:'Share Tech Mono',monospace;margin:4px 0;">{d['grade']}</div>
              <div style="font-family:'Share Tech Mono',monospace;font-size:0.75rem;
                          color:#4a6375;">{d['score']} pts</div>
            </div>
            """, unsafe_allow_html=True)


def render_port_tab(scan_res: dict):
    if scan_res.get("error"):
        st.error(f"⚠ Port scan error: {scan_res['error']}")

    open_ports = scan_res.get("open_ports", [])
    risky_ports = scan_res.get("risky_ports", [])

    col1, col2 = st.columns(2)
    with col1:
        st.markdown(f'<div style="font-family:\'Share Tech Mono\',monospace;color:#4a6375;font-size:0.8rem;letter-spacing:2px;margin-bottom:0.8rem;">OPEN PORTS DETECTED — {len(open_ports)} found</div>', unsafe_allow_html=True)
        if not open_ports:
            st.markdown(card('<span style="color:#00ff9f;">✓ No open ports detected</span>'))
        else:
            for p in open_ports:
                risky_match = next((r for r in risky_ports if r["port"] == p["port"]), None)
                border = "#ff2244" if risky_match and risky_match["risk"] == "critical" else \
                         "#ff8800" if risky_match and risky_match["risk"] in ["high", "medium"] else "#1e2d3d"
                svc = f'{p["product"]} {p["version"]}'.strip() or p["name"]
                st.markdown(card(
                    f'<span style="color:#00cfff;">:{p["port"]}</span>'
                    f'<span style="color:#c8d8e8;margin-left:12px;">{svc}</span>'
                    + (f' &nbsp;{badge(risky_match["risk"].upper(), border)}' if risky_match else
                       f' &nbsp;{badge("OPEN", "#4a6375")}'),
                    border_color=border
                ), unsafe_allow_html=True)

    with col2:
        st.markdown('<div style="font-family:\'Share Tech Mono\',monospace;color:#4a6375;font-size:0.8rem;letter-spacing:2px;margin-bottom:0.8rem;">RISK FINDINGS & REMEDIATION</div>', unsafe_allow_html=True)
        if not risky_ports:
            st.markdown(card('<span style="color:#00ff9f;">✓ No risky ports flagged</span>'))
        else:
            for r in risky_ports:
                color = "#ff2244" if r["risk"] == "critical" else \
                        "#ff8800" if r["risk"] == "high" else "#ffdd00"
                st.markdown(card(
                    f'{badge(r["risk"].upper(), color)}'
                    f'<span style="color:#c8d8e8;margin-left:10px;font-size:1rem;">Port {r["port"]} — {r["name"]}</span>'
                    f'<br><span style="color:#4a6375;font-size:0.8rem;margin-top:6px;display:block;">{r["reason"]}</span>'
                    f'<div style="margin-top:8px;padding:6px 10px;background:#0a1520;border-left:2px solid #00cfff;'
                    f'font-size:0.78rem;color:#00cfff;border-radius:2px;">🔧 {r["fix"]}</div>',
                    border_color=color + "44"
                ), unsafe_allow_html=True)


def render_web_tab(audit_res: dict):
    if audit_res.get("error"):
        st.error(f"⚠ Web audit error: {audit_res['error']}")

    https = audit_res.get("https", False)
    server = audit_res.get("server", "")
    x_powered = audit_res.get("x_powered_by", "")

    # Server info banner
    if server or x_powered:
        tech_str = " | ".join(filter(None, [server, x_powered]))
        st.markdown(card(
            f'<span style="color:#4a6375;font-size:0.75rem;letter-spacing:1px;">SERVER FINGERPRINT</span>'
            f'<span style="color:#ff8800;margin-left:12px;font-size:0.9rem;">{tech_str}</span>'
            f'<div style="font-size:0.75rem;color:#4a6375;margin-top:6px;">Consider hiding server version info to reduce attack surface. Use <code style="color:#00cfff;">server_tokens off</code> (Nginx) or <code style="color:#00cfff;">ServerTokens Prod</code> (Apache).</div>',
            border_color="#ff880044"
        ), unsafe_allow_html=True)

    https_color = "#00ff9f" if https else "#ff2244"
    https_text  = "✓ HTTPS Enabled" if https else "✗ HTTPS Not Detected — +20 pts"
    st.markdown(f'<div style="font-family:\'Share Tech Mono\',monospace;color:{https_color};font-size:0.85rem;margin-bottom:1rem;">{https_text}</div>', unsafe_allow_html=True)

    col1, col2 = st.columns(2)

    with col1:
        missing = audit_res.get("headers_missing", [])
        present = audit_res.get("headers_present", [])
        st.markdown(f'<div style="font-family:\'Share Tech Mono\',monospace;color:#4a6375;font-size:0.8rem;letter-spacing:2px;margin-bottom:0.8rem;">SECURITY HEADERS — {len(present)}/6 present</div>', unsafe_allow_html=True)

        for h in present:
            st.markdown(card(
                f'<span style="color:#00ff9f;">✓</span>'
                f'<span style="color:#c8d8e8;margin-left:10px;">{h["header"]}</span>'
                f'<span style="color:#4a6375;margin-left:8px;font-size:0.78rem;">({h["abbr"]})</span>',
                border_color="#00ff9f33"
            ), unsafe_allow_html=True)

        for h in missing:
            st.markdown(card(
                f'<span style="color:#ff2244;">✗</span>'
                f'<span style="color:#c8d8e8;margin-left:10px;">{h["header"]}</span>'
                f'<span style="color:#4a6375;margin-left:8px;font-size:0.78rem;">({h["abbr"]})</span>'
                f'<br><span style="color:#4a6375;font-size:0.78rem;margin-top:4px;display:block;">'
                f'Prevents: {h["attack"]}</span>'
                f'<div style="margin-top:6px;padding:5px 10px;background:#0a1520;border-left:2px solid #00cfff;'
                f'font-size:0.76rem;color:#00cfff;border-radius:2px;">🔧 {h["fix"]}</div>',
                border_color="#ff224433"
            ), unsafe_allow_html=True)

    with col2:
        cookies = audit_res.get("cookies", [])
        st.markdown(f'<div style="font-family:\'Share Tech Mono\',monospace;color:#4a6375;font-size:0.8rem;letter-spacing:2px;margin-bottom:0.8rem;">COOKIES — {len(cookies)} found</div>', unsafe_allow_html=True)
        if not cookies:
            st.markdown(card('<span style="color:#4a6375;">No cookies detected in response.</span>'))
        else:
            for c in cookies:
                issues = c.get("issues", [])
                border = "#ff224433" if issues else "#00ff9f33"
                flags_html = ""
                for flag in ["Secure", "HttpOnly", "SameSite"]:
                    key = flag.lower().replace("-", "")
                    val = c.get(key, c.get("samesite", "")) if flag == "SameSite" else c.get(key, False)
                    ok  = bool(val)
                    color = "#00ff9f" if ok else "#ff2244"
                    flags_html += f'<span style="color:{color};margin-right:12px;font-size:0.78rem;">'
                    flags_html += f'{"✓" if ok else "✗"} {flag}</span>'

                issues_html = ""
                for iss in issues:
                    issues_html += (f'<div style="margin-top:6px;padding:5px 10px;background:#0a1520;'
                                    f'border-left:2px solid #00cfff;font-size:0.76rem;color:#00cfff;'
                                    f'border-radius:2px;">🔧 {iss["fix"]}</div>')

                st.markdown(card(
                    f'<span style="color:#c8d8e8;">{c["name"]}</span><br>'
                    f'<div style="margin-top:6px;">{flags_html}</div>'
                    f'{issues_html}',
                    border_color=border
                ), unsafe_allow_html=True)


def render_ssl_tab(ssl_res: dict):
    if ssl_res.get("error"):
        err_has_score = ssl_res.get("risk_score", 0) > 0
        color = "#ff2244" if err_has_score else "#ff8800"
        st.markdown(card(
            f'<span style="color:{color};">⚠ {ssl_res["error"]}</span>',
            border_color=color + "44"
        ), unsafe_allow_html=True)
        if not ssl_res.get("valid"):
            st.markdown(card(
                '<div style="color:#00cfff;font-size:0.78rem;">🔧 Obtain a valid SSL certificate from a trusted CA. '
                'Let\'s Encrypt offers free certificates — use Certbot for automated renewal.</div>',
                border_color="#00cfff44"
            ), unsafe_allow_html=True)
            return

    valid   = ssl_res.get("valid", False)
    expired = ssl_res.get("expired", False)
    self_sg = ssl_res.get("self_signed", False)

    col1, col2 = st.columns(2)

    with col1:
        st.markdown('<div style="font-family:\'Share Tech Mono\',monospace;color:#4a6375;font-size:0.8rem;letter-spacing:2px;margin-bottom:0.8rem;">CERTIFICATE DETAILS</div>', unsafe_allow_html=True)

        items = [
            ("STATUS",    ("✓ Valid" if valid and not expired else "✗ Expired" if expired else "✗ Invalid"),
             "#00ff9f" if (valid and not expired) else "#ff2244"),
            ("SUBJECT",   ssl_res.get("subject", "—"),   "#c8d8e8"),
            ("ISSUER",    ssl_res.get("issuer", "—"),    "#c8d8e8"),
            ("EXPIRES",   ssl_res.get("expires", "—"),   "#c8d8e8"),
            ("TLS",       ssl_res.get("tls_version", "—"), "#00cfff"),
        ]
        days = ssl_res.get("days_left")
        if days is not None:
            d_color = "#00ff9f" if days > 60 else "#ffdd00" if days > 30 else "#ff2244"
            items.append(("DAYS LEFT", str(days), d_color))

        for key, val, color in items:
            st.markdown(card(
                f'<span style="color:#4a6375;font-size:0.72rem;letter-spacing:1px;">{key}</span>'
                f'<span style="color:{color};margin-left:12px;font-size:0.9rem;">{val}</span>'
            ), unsafe_allow_html=True)

    with col2:
        st.markdown('<div style="font-family:\'Share Tech Mono\',monospace;color:#4a6375;font-size:0.8rem;letter-spacing:2px;margin-bottom:0.8rem;">FINDINGS & REMEDIATION</div>', unsafe_allow_html=True)

        findings = []
        if expired:
            findings.append(("CRITICAL", "#ff2244", "Certificate has expired.", "Renew your SSL certificate immediately using your CA or Certbot."))
        if self_sg:
            findings.append(("HIGH", "#ff8800", "Certificate is self-signed — not trusted by browsers.", "Replace with a CA-signed certificate. Use Let's Encrypt (free) or a commercial CA."))
        if days is not None and 0 < days <= 30:
            findings.append(("WARNING", "#ffdd00", f"Certificate expires in {days} days.", "Renew your certificate before it expires to avoid service disruption."))
        if not ssl_res.get("error") and valid and not expired and not self_sg:
            if days is None or days > 30:
                findings.append(("PASS", "#00ff9f", "Certificate is valid and trusted.", ""))

        if not findings:
            findings.append(("PASS", "#00ff9f", "No SSL issues detected.", ""))

        for sev, color, reason, fix in findings:
            st.markdown(card(
                f'{badge(sev, color)}'
                f'<span style="color:#c8d8e8;margin-left:10px;font-size:0.88rem;">{reason}</span>'
                + (f'<div style="margin-top:8px;padding:5px 10px;background:#0a1520;border-left:2px solid #00cfff;font-size:0.76rem;color:#00cfff;border-radius:2px;">🔧 {fix}</div>' if fix else ""),
                border_color=color + "44"
            ), unsafe_allow_html=True)


def render_dns_tab(dns_res: dict):
    col1, col2 = st.columns(2)

    with col1:
        st.markdown('<div style="font-family:\'Share Tech Mono\',monospace;color:#4a6375;font-size:0.8rem;letter-spacing:2px;margin-bottom:0.8rem;">EMAIL AUTHENTICATION RECORDS</div>', unsafe_allow_html=True)

        for key, label, icon in [("spf", "SPF", "📨"), ("dmarc", "DMARC", "🛡"), ("dkim", "DKIM", "🔑")]:
            d = dns_res.get(key, {})
            present = d.get("present", False)
            record  = d.get("record", "")
            issues  = d.get("issues", [])
            fix     = d.get("fix", "")
            border  = "#00ff9f33" if present and not issues else "#ff224433" if not present else "#ffdd0033"

            selector_info = ""
            if key == "dkim" and present:
                selector_info = f' &nbsp;<span style="color:#4a6375;font-size:0.75rem;">selector: {d.get("selector_found","")}</span>'

            st.markdown(card(
                f'{icon} <span style="color:#c8d8e8;font-size:0.95rem;font-weight:600;">{label}</span>'
                f'&nbsp;&nbsp;{badge("PRESENT" if present else "MISSING", "#00ff9f" if present else "#ff2244")}'
                f'{selector_info}'
                + (f'<div style="margin-top:6px;font-size:0.76rem;color:#4a6375;word-break:break-all;">{record[:100]}{"..." if len(record) > 100 else ""}</div>' if record else "")
                + (f'<div style="margin-top:4px;font-size:0.76rem;color:#ff8800;">{" ".join(issues)}</div>' if issues else "")
                + (f'<div style="margin-top:6px;padding:5px 10px;background:#0a1520;border-left:2px solid #00cfff;font-size:0.76rem;color:#00cfff;border-radius:2px;">🔧 {fix}</div>' if fix else ""),
                border_color=border
            ), unsafe_allow_html=True)

    with col2:
        subs = dns_res.get("subdomains", {})
        found = subs.get("found", [])
        st.markdown(f'<div style="font-family:\'Share Tech Mono\',monospace;color:#4a6375;font-size:0.8rem;letter-spacing:2px;margin-bottom:0.8rem;">SUBDOMAIN ENUMERATION — {len(found)} found</div>', unsafe_allow_html=True)

        if not found:
            st.markdown(card('<span style="color:#4a6375;">No subdomains resolved from common wordlist.</span>'))
        else:
            for s in found:
                risky = s.get("risky", False)
                border = "#ff244433" if risky else "#1e2d3d"
                ips_str = ", ".join(s["ips"][:2])
                st.markdown(card(
                    f'{"⚠ " if risky else ""}<span style="color:{"#ff8800" if risky else "#00cfff"};">{s["subdomain"]}</span>'
                    f'<span style="color:#4a6375;margin-left:10px;font-size:0.78rem;">{ips_str}</span>'
                    + (f'<div style="font-size:0.75rem;color:#4a6375;margin-top:4px;">{s["reason"]}</div>' if s["reason"] else "")
                    + (f'<div style="margin-top:5px;padding:4px 10px;background:#0a1520;border-left:2px solid #00cfff;font-size:0.75rem;color:#00cfff;border-radius:2px;">🔧 {s["fix"]}</div>' if s["fix"] else ""),
                    border_color=border
                ), unsafe_allow_html=True)


# ─────────────────────────────────────────────
#  MAIN APP
# ─────────────────────────────────────────────

def run_scan(domain: str):
    """Run all 4 modules with progress tracking."""
    results = {}
    progress = st.progress(0)
    status   = st.empty()

    def update(pct, msg):
        progress.progress(pct)
        status.markdown(
            f'<div style="font-family:\'Share Tech Mono\',monospace;color:#00ff9f;font-size:0.85rem;">'
            f'[ {pct}% ] {msg}</div>', unsafe_allow_html=True
        )

    update(5,  "Initialising scan modules...")

    # Run DNS and Web in parallel since they don't need nmap
    dns_result  = {}
    audit_result = {}

    def do_dns():
        nonlocal dns_result
        dns_result = dns_checker.full_dns_check(domain)

    def do_web():
        nonlocal audit_result
        audit_result = web_audit.audit(domain)

    update(15, "Launching DNS & Web audit threads...")
    t_dns = threading.Thread(target=do_dns)
    t_web = threading.Thread(target=do_web)
    t_dns.start(); t_web.start()

    update(30, "Running port scan (Nmap)...")
    scan_result = scanner.scan(domain)

    update(60, "Inspecting SSL/TLS certificate...")
    ssl_result = ssl_checker.check(domain)

    update(80, "Waiting for DNS & Web threads...")
    t_dns.join(); t_web.join()

    update(95, "Calculating risk score & grade...")
    grade_result = scorer.calculate(scan_result, audit_result, ssl_result, dns_result)

    update(100, "Scan complete.")
    progress.empty()
    status.empty()

    return scan_result, audit_result, ssl_result, dns_result, grade_result


def main():
    # ── Header ──
    st.markdown("""
    <div style="margin-bottom:2rem;">
      <div style="font-family:'Share Tech Mono',monospace;font-size:0.75rem;
                  color:#4a6375;letter-spacing:4px;margin-bottom:4px;">
        [ NETWORK & WEB SECURITY AUDITOR ]
      </div>
      <div style="font-size:2.8rem;font-weight:700;font-family:'Rajdhani',sans-serif;
                  letter-spacing:3px;color:#c8d8e8;line-height:1;">
        AR<span style="color:#00ff9f;">GUS</span>
        <span style="font-size:0.9rem;font-family:'Share Tech Mono',monospace;
                     color:#4a6375;letter-spacing:2px;margin-left:12px;vertical-align:middle;">v1.0</span>
      </div>
      <div style="font-family:'Share Tech Mono',monospace;font-size:0.8rem;color:#4a6375;margin-top:4px;">
        All-seeing security auditor &nbsp;—&nbsp; Port Scanner &nbsp;|&nbsp; HTTP Headers &nbsp;|&nbsp; SSL/TLS &nbsp;|&nbsp; DNS/SPF/DMARC &nbsp;|&nbsp; Subdomain Enumeration
      </div>
    </div>
    """, unsafe_allow_html=True)

    # ── Input row ──
    col_inp, col_btn = st.columns([5, 1])
    with col_inp:
        domain_input = st.text_input(
            label="domain",
            placeholder="github.com",
            label_visibility="collapsed",
            key="domain_input"
        )
    with col_btn:
        scan_clicked = st.button("SCAN →", type="primary", use_container_width=True)

    st.markdown('<div style="font-family:\'Share Tech Mono\',monospace;font-size:0.73rem;color:#4a6375;margin-top:-0.5rem;margin-bottom:1.5rem;">Enter a domain without http:// — e.g. github.com &nbsp;|&nbsp; Nmap must be installed on the host machine.</div>', unsafe_allow_html=True)

    # ── Run scan ──
    if scan_clicked and domain_input.strip():
        domain = domain_input.strip().replace("https://", "").replace("http://", "").rstrip("/")

        with st.spinner(""):
            scan_res, audit_res, ssl_res, dns_res, grade_res = run_scan(domain)

        st.markdown("---")

        # ── Grade header ──
        render_grade_header(grade_res, domain)

        # ── Subscores + radar ──
        col_scores, col_radar = st.columns([3, 2])
        with col_scores:
            st.markdown('<div style="font-family:\'Share Tech Mono\',monospace;color:#4a6375;font-size:0.78rem;letter-spacing:2px;margin-bottom:0.8rem;">CATEGORY BREAKDOWN</div>', unsafe_allow_html=True)
            render_subscores(grade_res["breakdown"])
        with col_radar:
            st.markdown('<div style="font-family:\'Share Tech Mono\',monospace;color:#4a6375;font-size:0.78rem;letter-spacing:2px;margin-bottom:0.8rem;">SECURITY RADAR</div>', unsafe_allow_html=True)
            render_radar(grade_res["breakdown"])

        st.markdown("---")

        # ── Tabbed details ──
        tabs = st.tabs(["⚡  PORTS", "🌐  WEB HEADERS", "🔒  SSL / TLS", "📡  DNS & SUBDOMAINS"])

        with tabs[0]:
            render_port_tab(scan_res)
        with tabs[1]:
            render_web_tab(audit_res)
        with tabs[2]:
            render_ssl_tab(ssl_res)
        with tabs[3]:
            render_dns_tab(dns_res)

    elif scan_clicked and not domain_input.strip():
        st.warning("Please enter a domain name.")
    else:
        # ── Landing state ──
        st.markdown("""
        <div style="margin-top:3rem;text-align:center;">
          <div style="font-family:'Share Tech Mono',monospace;font-size:0.85rem;color:#1e2d3d;
                      letter-spacing:3px;margin-bottom:1.5rem;">── SCAN MODULES ──</div>
          <div style="display:flex;justify-content:center;gap:1.5rem;flex-wrap:wrap;">
        """, unsafe_allow_html=True)

        modules_info = [
            ("⚡", "PORT SCAN",   "Nmap scans 10 common ports for open services"),
            ("🌐", "HTTP AUDIT",  "Checks 6 critical security headers & cookie flags"),
            ("🔒", "SSL / TLS",   "Validates certificate, expiry, issuer & TLS version"),
            ("📡", "DNS SECURITY","SPF, DMARC, DKIM + subdomain enumeration"),
        ]
        cols = st.columns(4)
        for col, (icon, title, desc) in zip(cols, modules_info):
            with col:
                st.markdown(f"""
                <div style="background:#0f1419;border:1px solid #1e2d3d;border-radius:8px;
                            padding:1.5rem 1rem;text-align:center;">
                  <div style="font-size:1.8rem;margin-bottom:0.5rem;">{icon}</div>
                  <div style="font-family:'Share Tech Mono',monospace;font-size:0.72rem;
                              color:#00ff9f;letter-spacing:2px;margin-bottom:0.4rem;">{title}</div>
                  <div style="font-family:'Rajdhani',sans-serif;font-size:0.85rem;color:#4a6375;">{desc}</div>
                </div>
                """, unsafe_allow_html=True)


if __name__ == "__main__":
    main()
