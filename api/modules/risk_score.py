"""
Business Risk Score — pure Python weighted sum.
No scikit-learn. No model.pkl. Deterministic arithmetic only.
"""
from typing import Any

# ─────────────────────────────────────────────
# Weights per finding category
# Spec-defined values, applied per finding
# ─────────────────────────────────────────────
WEIGHTS: dict[str, int] = {
    # SSL
    "ssl_expired":          -30,
    "ssl_expiring_soon":    -20,   # < 7 days
    "no_hsts":              -15,   # Missing HSTS header category
    # DNS / Email
    "no_spf":               -12,
    "no_dmarc":             -12,
    "dmarc_weak":           -6,
    # Injection
    "xss_found":            -25,
    "sqli_found":           -30,
    "sqli_code":            -30,
    "path_traversal":       -20,
    # Breach
    "breach_found":         -20,
    # Blacklist
    "blacklisted":          -35,
    # Secrets
    "hardcoded_secret":     -25,
    "private_key_committed": -30,
    "exposed_env":          -25,
    # Port scanning
    "dangerous_open_port":  -10,
    # Headers — per missing header
    "headers":              -5,
    # CVE
    "cve_critical":         -25,
    "cve_high":             -15,
    # Auth / Code
    "debug_mode":           -15,
    "jwt_none_alg":         -20,
    "weak_crypto":          -10,
    "shell_injection":      -20,
    "dangerous_code":       -15,
    "insecure_deserialization": -15,
    "dangerous_deserialization": -15,
    "subdomain_takeover":   -20,
    "database_dump":        -10,
    "exposed_config":       -15,
    # India / misc
    "http_form":            -15,
    "cms_cve":              -15,
}


def compute_risk_score(findings: list[dict]) -> int:
    """
    Start at 100, subtract percentage based on severity.
    Returns 0–100 integer score.
    A higher score = safer.
    """
    score = 100.0
    for finding in findings:
        sev = finding.get("severity", "low")
        if sev == "critical":
            score -= (score * 0.15)  # 15% drop per critical
        elif sev == "medium":
            score -= (score * 0.05)   # 5% drop per medium
        else:
            score -= (score * 0.02)   # 2% drop per low

    return int(max(0, min(100, score)))


def score_label(score: int) -> str:
    """Return a human-readable label for the score."""
    if score >= 70:
        return "Good"
    elif score >= 40:
        return "At Risk"
    else:
        return "Critical"


def score_color(score: int) -> str:
    """Return the hex color for the score."""
    if score >= 70:
        return "#10b981"  # green
    elif score >= 40:
        return "#f59e0b"  # amber
    else:
        return "#ef4444"  # red
