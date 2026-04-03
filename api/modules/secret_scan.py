"""
Secret & key detection via regex patterns.
Scans file contents for hardcoded credentials, API keys, private keys.
"""
import re
from typing import Any

# ─────────────────────────────────────────────
# Regex patterns for secret detection
# Each entry: (name, pattern, severity, description)
# ─────────────────────────────────────────────
SECRET_PATTERNS = [
    ("AWS Access Key",         r"AKIA[0-9A-Z]{16}",                                                "critical"),
    ("AWS Secret Key",         r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",         "critical"),
    ("GCP API Key",            r"AIza[0-9A-Za-z\-_]{35}",                                          "critical"),
    ("GCP Service Account",    r'"type":\s*"service_account"',                                      "critical"),
    ("GitHub Token",           r"ghp_[0-9a-zA-Z]{36}|gho_[0-9a-zA-Z]{36}|github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}", "critical"),
    ("Stripe Secret Key",      r"sk_live_[0-9a-zA-Z]{24,}",                                        "critical"),
    ("Stripe Publishable Key", r"pk_live_[0-9a-zA-Z]{24,}",                                        "medium"),
    ("Twilio Account SID",     r"AC[a-z0-9]{32}",                                                  "medium"),
    ("Twilio Auth Token",      r"(?i)twilio.{0,20}['\"][0-9a-f]{32}['\"]",                         "critical"),
    ("JWT Secret",             r"(?i)(jwt.?secret|jwt.?key).{0,10}[=:]\s*['\"][\w\-+=/.]{8,}['\"]", "critical"),
    ("RSA Private Key",        r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",                  "critical"),
    ("Generic Password",       r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{4,}['\"]",         "critical"),
    ("Generic Secret",         r"(?i)(secret|api_secret|client_secret)\s*[=:]\s*['\"][^'\"]{8,}['\"]", "critical"),
    ("Generic API Key",        r"(?i)(api_key|apikey|api.key)\s*[=:]\s*['\"][^'\"]{8,}['\"]",      "medium"),
    ("SendGrid API Key",       r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}",                     "critical"),
    ("Slack Token",            r"xox[baprs]-[0-9a-zA-Z]{10,48}",                                   "critical"),
    ("Slack Webhook",          r"https://hooks\.slack\.com/services/[A-Z0-9/]{44}",                 "medium"),
    ("NPM Token",              r"npm_[A-Za-z0-9]{36}",                                             "critical"),
    ("Heroku API Key",         r"(?i)heroku.{0,20}['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]", "critical"),
    ("Database URL",           r"(?i)(postgres|mysql|mongodb|redis)://[^:\s]+:[^@\s]+@[^\s]+",     "critical"),
    (".env Password Line",     r"(?i)^(DB_PASSWORD|DATABASE_PASSWORD|MYSQL_PASSWORD|POSTGRES_PASSWORD)\s*=\s*.+", "critical"),
]

# Compiled patterns
COMPILED_PATTERNS = [
    (name, re.compile(pattern, re.MULTILINE), severity)
    for name, pattern, severity in SECRET_PATTERNS
]

# Files to skip (binary / minified / test fixtures)
SKIP_EXTENSIONS = {".png", ".jpg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot",
                   ".pdf", ".zip", ".tar", ".gz", ".min.js", ".min.css", ".map"}
SKIP_DIRS = {"node_modules", ".git", "vendor", "dist", "build", "__pycache__"}

DESCRIPTIONS = {
    "critical": "This secret gives an attacker access to a critical service. If committed to a repository, it may already be known to automated scanners that harvest credentials from public repos.",
    "medium": "This key or credential could be misused if discovered by an attacker.",
}

FIX_STEPS = """1. Immediately revoke/rotate this secret in the service it belongs to
2. Never commit secrets to version control — use environment variables instead
3. Add this file pattern to .gitignore
4. Install git-secrets or truffleHog to prevent future leaks
5. If this was ever pushed to a public repository, assume it is compromised — rotate immediately"""


def _mask_value(value: str) -> str:
    """Show first 4 and last 4 chars only."""
    if len(value) <= 8:
        return "****"
    return f"{value[:4]}...{value[-4:]}"


async def scan_secrets(files: list[dict]) -> list[dict]:
    findings = []
    seen_signatures = set()  # Deduplicate identical secrets across files

    for file_obj in files:
        path = file_obj.get("path", "")
        content = file_obj.get("content", "")

        # Skip binary / minified / irrelevant files
        if any(path.endswith(ext) for ext in SKIP_EXTENSIONS):
            continue
        if any(f"/{skip}/" in f"/{path}" or path.startswith(f"{skip}/") for skip in SKIP_DIRS):
            continue

        lines = content.split("\n")

        for name, pattern, severity in COMPILED_PATTERNS:
            for line_num, line in enumerate(lines, 1):
                match = pattern.search(line)
                if match:
                    matched_val = match.group(0)
                    sig = f"{name}:{_mask_value(matched_val)}"
                    if sig in seen_signatures:
                        continue
                    seen_signatures.add(sig)

                    # Get 3 lines of context
                    start = max(0, line_num - 2)
                    end = min(len(lines), line_num + 1)
                    context = "\n".join(f"  {i+start+1}: {lines[i]}" for i in range(end - start))

                    findings.append({
                        "severity": severity,
                        "category": "hardcoded_secret" if severity == "critical" else "potential_secret",
                        "title": f"Hardcoded {name} Found",
                        "description": f"A {name} was found hardcoded in your source code at {path}:{line_num}. {DESCRIPTIONS[severity]}",
                        "fix_steps": FIX_STEPS,
                        "affected_asset": path,
                        "line_number": line_num,
                        "compliance": ["SOC2 CC6.1", "ISO 27001 A.8.1"],
                        "metadata": {
                            "secret_type": name,
                            "masked_value": _mask_value(matched_val),
                            "context": context,
                        }
                    })

    return findings
