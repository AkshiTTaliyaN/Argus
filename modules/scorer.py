"""
scorer.py — Aggregates all module risk scores into a final grade.
"""

GRADE_MAP = [
    (0,   0,  "A", "Excellent",  "#00ff9f", "No significant issues detected."),
    (1,   20, "B", "Good",       "#aaff00", "Minor issues — review recommended."),
    (21,  40, "C", "Fair",       "#ffdd00", "Some issues need attention."),
    (41,  70, "D", "Poor",       "#ff8800", "Serious vulnerabilities present."),
    (71, 999, "F", "Critical",   "#ff2244", "Major vulnerabilities detected. Immediate action required."),
]


def calculate(scan_result: dict, audit_result: dict, ssl_result: dict, dns_result: dict) -> dict:
    """
    Sums risk scores from all modules and returns grade, color, and summary.
    """
    port_score = scan_result.get("risk_score", 0)
    web_score  = audit_result.get("risk_score", 0)
    ssl_score  = ssl_result.get("risk_score", 0)
    dns_score  = dns_result.get("risk_score", 0)

    total = port_score + web_score + ssl_score + dns_score

    grade_entry = GRADE_MAP[-1]
    for lo, hi, grade, label, color, summary in GRADE_MAP:
        if lo <= total <= hi:
            grade_entry = (lo, hi, grade, label, color, summary)
            break

    _, _, grade, label, color, summary = grade_entry

    # Per-category grades
    def _grade(score):
        for lo, hi, g, lbl, clr, _ in GRADE_MAP:
            if lo <= score <= hi:
                return g, clr
        return "F", "#ff2244"

    return {
        "grade":        grade,
        "label":        label,
        "color":        color,
        "summary":      summary,
        "total_risk":   total,
        "breakdown": {
            "network": {"score": port_score, "grade": _grade(port_score)[0], "color": _grade(port_score)[1]},
            "web":     {"score": web_score,  "grade": _grade(web_score)[0],  "color": _grade(web_score)[1]},
            "ssl":     {"score": ssl_score,  "grade": _grade(ssl_score)[0],  "color": _grade(ssl_score)[1]},
            "dns":     {"score": dns_score,  "grade": _grade(dns_score)[0],  "color": _grade(dns_score)[1]},
        }
    }
