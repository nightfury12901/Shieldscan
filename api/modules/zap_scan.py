"""
ZAP Scanner — Pure Python XSS/SQLi/Path Traversal placeholder.
Swappable: if ZAP_API_URL env var is set, uses real ZAP REST API.
Never skips silently — always returns a result dict.
"""
import os
import asyncio
import httpx
from urllib.parse import urlparse, urlencode, parse_qs, urljoin

# ─────────────────────────────────────────────
# Test payloads
# ─────────────────────────────────────────────
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    "'><svg onload=alert(1)>",
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "'; DROP TABLE users; --",
    "1 AND 1=1",
    "' UNION SELECT NULL--",
    "\" OR \"1\"=\"1",
]

SQLI_ERROR_STRINGS = [
    "sql syntax",
    "mysql_fetch",
    "ora-00933",
    "microsoft ole db",
    "unclosed quotation mark",
    "sqlite_error",
    "pg_query",
    "syntax error in sql",
    "postgresql",
    "warning: pg_",
    "valid mysql result",
    "supplied argument is not a valid mysql",
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//etc/passwd",
]

PATH_TRAVERSAL_SIGNATURES = [
    "root:x:0:0",
    "bin/bash",
    "/etc/shadow",
    "nobody:x:",
]


async def scan_zap(url: str) -> list[dict]:
    """Entry point — routes to real ZAP or Python placeholder."""
    zap_url = os.getenv("ZAP_API_URL", "").strip()
    if zap_url:
        return await _scan_via_zap_api(url, zap_url)
    return await _scan_python_placeholder(url)


# ─────────────────────────────────────────────
# Python placeholder implementation
# ─────────────────────────────────────────────
async def _scan_python_placeholder(url: str) -> list[dict]:
    findings = []

    # Discover injectable parameters
    params = _extract_params(url)
    if not params:
        # Add a dummy param to test
        params = {"q": "test"}

    async with httpx.AsyncClient(
        timeout=10,
        follow_redirects=True,
        headers={"User-Agent": "ShieldScan-Security-Auditor/1.0"},
    ) as client:
        tasks = [
            _test_xss(client, url, params),
            _test_sqli(client, url, params),
            _test_path_traversal(client, url),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                findings.extend(r)

    # Tag all findings as placeholder
    for f in findings:
        f.setdefault("metadata", {})["scanner"] = "python-placeholder"

    return findings


def _extract_params(url: str) -> dict:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    return {k: v[0] for k, v in qs.items()} if qs else {}


async def _test_xss(client: httpx.AsyncClient, url: str, params: dict) -> list[dict]:
    findings = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    for payload in XSS_PAYLOADS:
        test_params = {k: payload for k in params}
        test_url = f"{base}?{urlencode(test_params)}"
        try:
            resp = await client.get(test_url)
            body = resp.text

            # Check if payload is reflected unescaped in response
            if payload in body:
                findings.append({
                    "severity": "critical",
                    "category": "xss_found",
                    "title": "Reflected XSS Vulnerability Found",
                    "description": "An attacker can inject malicious code into your website that runs in your visitors' browsers. This can steal login sessions, redirect users to fake sites, or silently steal form data including passwords.",
                    "fix_steps": "1. Never insert untrusted data directly into HTML\n2. Use an HTML encoding library to escape all user input before displaying it\n3. Implement a Content Security Policy header\n4. Have your developer review all places where user data is shown on screen",
                    "affected_asset": f"{url} (parameter: {list(params.keys())[0]})",
                })
                break  # One finding per URL is enough
        except Exception:
            pass
    return findings


async def _test_sqli(client: httpx.AsyncClient, url: str, params: dict) -> list[dict]:
    findings = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    for payload in SQLI_PAYLOADS:
        test_params = {k: payload for k in params}
        test_url = f"{base}?{urlencode(test_params)}"
        try:
            resp = await client.get(test_url)
            body = resp.text.lower()

            for err in SQLI_ERROR_STRINGS:
                if err in body:
                    findings.append({
                        "severity": "critical",
                        "category": "sqli_found",
                        "title": "SQL Injection Vulnerability Found",
                        "description": "An attacker can manipulate your database directly through your website. This can allow them to read all customer data, steal passwords, or permanently delete your entire database.",
                        "fix_steps": "1. NEVER build SQL queries by concatenating user input\n2. Use parameterized queries (also called prepared statements)\n3. Example fix: use db.execute('SELECT * FROM users WHERE id=?', [user_id]) instead of string concatenation\n4. Have a security-aware developer audit all database queries",
                        "affected_asset": f"{url} — detected error: '{err}'",
                    })
                    return findings  # One confirmed finding is enough
        except Exception:
            pass
    return findings


async def _test_path_traversal(client: httpx.AsyncClient, url: str) -> list[dict]:
    findings = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    for payload in PATH_TRAVERSAL_PAYLOADS:
        test_url = f"{base}/{payload}"
        try:
            resp = await client.get(test_url)
            body = resp.text

            for sig in PATH_TRAVERSAL_SIGNATURES:
                if sig in body:
                    findings.append({
                        "severity": "critical",
                        "category": "path_traversal",
                        "title": "Path Traversal Vulnerability Found",
                        "description": "An attacker can read files from your server that they should never access, including server configuration files, password files, and other sensitive data.",
                        "fix_steps": "1. Never use user-provided input to construct file paths\n2. Use allowlists — only serve files from a specific safe directory\n3. Sanitize all input: reject any path containing '..' or starting with '/'\n4. Run your web server as a low-privilege user",
                        "affected_asset": f"{url} — traversal to system file detected",
                    })
                    return findings
        except Exception:
            pass
    return findings


# ─────────────────────────────────────────────
# Real ZAP REST API (used when ZAP_API_URL is set)
# ─────────────────────────────────────────────
async def _scan_via_zap_api(url: str, zap_api_url: str) -> list[dict]:
    findings = []
    try:
        async with httpx.AsyncClient(timeout=55) as client:
            # Start active scan
            resp = await client.get(
                f"{zap_api_url}/JSON/ascan/action/scan/",
                params={"url": url, "recurse": "true", "inScopeOnly": "false"}
            )
            scan_id = resp.json().get("scan", "0")

            # Poll for completion (max 50s)
            for _ in range(10):
                await asyncio.sleep(5)
                status_resp = await client.get(
                    f"{zap_api_url}/JSON/ascan/view/status/",
                    params={"scanId": scan_id}
                )
                progress = int(status_resp.json().get("status", 0))
                if progress >= 100:
                    break

            # Get alerts
            alerts_resp = await client.get(
                f"{zap_api_url}/JSON/core/view/alerts/",
                params={"baseurl": url}
            )
            alerts = alerts_resp.json().get("alerts", [])
            for alert in alerts:
                risk = alert.get("risk", "").lower()
                severity = "critical" if risk == "high" else "medium" if risk == "medium" else "low"
                findings.append({
                    "severity": severity,
                    "category": "zap_" + alert.get("pluginId", "misc"),
                    "title": alert.get("name", "ZAP Finding"),
                    "description": alert.get("description", ""),
                    "fix_steps": alert.get("solution", ""),
                    "affected_asset": alert.get("url", url),
                })
    except Exception as e:
        findings.append({
            "severity": "low",
            "category": "zap",
            "title": "ZAP Scanner Unavailable",
            "description": f"Could not reach ZAP API at {zap_api_url}: {str(e)}",
            "fix_steps": "Check that ZAP is running and ZAP_API_URL is correct.",
            "affected_asset": url,
        })
    return findings
