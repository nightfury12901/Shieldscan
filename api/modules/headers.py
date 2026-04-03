"""
HTTP Security Headers scanner.
Checks presence and configuration of key security headers.
"""
import asyncio
import httpx
from typing import Any

REQUIRED_HEADERS = {
    "Content-Security-Policy": {
        "severity": "critical",
        "category": "headers",
        "title": "Missing Content Security Policy (CSP)",
        "description": "Your website has no Content Security Policy header. This means attackers can inject malicious scripts into your pages.",
        "fix_steps": "1. Add the header: Content-Security-Policy: default-src 'self'\n2. Work with your developer to allow only trusted sources for scripts, styles, and images.\n3. Test your policy at https://csp-evaluator.withgoogle.com",
    },
    "Strict-Transport-Security": {
        "severity": "medium",
        "category": "headers",
        "title": "Missing HTTP Strict Transport Security (HSTS)",
        "description": "Your site doesn't force HTTPS connections. Attackers can intercept traffic between your visitors and your site.",
        "fix_steps": "1. Add: Strict-Transport-Security: max-age=31536000; includeSubDomains\n2. This tells browsers to always use HTTPS for your site for 1 year.",
    },
    "X-Frame-Options": {
        "severity": "medium",
        "category": "headers",
        "title": "Missing X-Frame-Options",
        "description": "Your site can be embedded in another website's iframe, which could trick your users into clicking things they didn't intend to (clickjacking).",
        "fix_steps": "1. Add: X-Frame-Options: DENY\n2. Or if you need embedding: X-Frame-Options: SAMEORIGIN",
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "category": "headers",
        "title": "Missing X-Content-Type-Options",
        "description": "Browsers might incorrectly guess your files' types, which can open up attack vectors.",
        "fix_steps": "1. Add: X-Content-Type-Options: nosniff",
    },
    "Referrer-Policy": {
        "severity": "low",
        "category": "headers",
        "title": "Missing Referrer-Policy",
        "description": "Your site may leak the full URL of your pages to other websites a user navigates to.",
        "fix_steps": "1. Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "severity": "low",
        "category": "headers",
        "title": "Missing Permissions-Policy",
        "description": "Your site doesn't restrict browser features (camera, microphone, geolocation) that you may not use.",
        "fix_steps": "1. Add: Permissions-Policy: geolocation=(), camera=(), microphone=()",
    },
}

INSECURE_HEADER_VALUES = {
    "X-XSS-Protection": {
        "bad_value": "0",
        "severity": "low",
        "category": "headers",
        "title": "XSS Protection Explicitly Disabled",
        "description": "Your site has explicitly disabled the browser's built-in XSS filter.",
        "fix_steps": "1. Either remove the X-XSS-Protection header or set it to: X-XSS-Protection: 1; mode=block",
    }
}

async def scan_headers(url: str) -> list[dict]:
    findings = []
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            resp = await client.get(url, headers={"User-Agent": "ShieldScan/1.0"})
            headers = {k.lower(): v for k, v in resp.headers.items()}

            for header_name, meta in REQUIRED_HEADERS.items():
                if header_name.lower() not in headers:
                    findings.append({
                        **meta,
                        "affected_asset": header_name,
                    })

            for header_name, meta in INSECURE_HEADER_VALUES.items():
                val = headers.get(header_name.lower(), "")
                if val.strip() == meta["bad_value"]:
                    findings.append({
                        "severity": meta["severity"],
                        "category": meta["category"],
                        "title": meta["title"],
                        "description": meta["description"],
                        "fix_steps": meta["fix_steps"],
                        "affected_asset": f"{header_name}: {val}",
                    })

    except Exception as e:
        findings.append({
            "severity": "low",
            "category": "headers",
            "title": "Could not retrieve HTTP headers",
            "description": f"Failed to connect to the target: {str(e)}",
            "fix_steps": "Verify the URL is accessible and returns HTTP responses.",
            "affected_asset": url,
        })
    return findings
