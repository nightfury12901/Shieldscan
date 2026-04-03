"""
CMS Vulnerability scanner via WPScan API.
Gracefully skips if WPSCAN_API_KEY is not set.
"""
import os
import asyncio
import httpx
import re
from urllib.parse import urlparse


CMS_SIGNATURES = {
    "wordpress": ["/wp-content/", "/wp-includes/", "wp-json"],
    "joomla": ["/components/com_", "Joomla!", "/templates/"],
    "drupal": ["/sites/default/", "Drupal.settings", "X-Generator: Drupal"],
}


async def scan_cms(url: str) -> list[dict]:
    findings = []
    wpscan_key = os.getenv("WPSCAN_API_KEY", "")

    # Detect CMS type
    cms_type = await _detect_cms(url)

    if not cms_type:
        return []  # No known CMS detected

    if cms_type == "wordpress" and wpscan_key:
        findings.extend(await _wpscan_check(url, wpscan_key))
    elif cms_type == "wordpress" and not wpscan_key:
        findings.append({
            "severity": "low",
            "category": "cms",
            "title": "WordPress Detected — CMS Vulnerability Scan Skipped",
            "description": "Your site appears to run WordPress. A full vulnerability scan was skipped because the WPScan API key is not configured.",
            "fix_steps": "1. Keep WordPress core, themes, and plugins updated\n2. Remove unused plugins and themes\n3. Use a security plugin like Wordfence\n4. Configure a WPScan API key to enable full scanning",
            "affected_asset": url,
        })
    elif cms_type in ("joomla", "drupal"):
        findings.append({
            "severity": "low",
            "category": "cms",
            "title": f"{cms_type.capitalize()} CMS Detected",
            "description": f"Your site appears to run {cms_type.capitalize()}. Keep it and all extensions up to date to avoid known vulnerabilities.",
            "fix_steps": f"1. Check {cms_type}.org for security advisories\n2. Update to the latest stable version regularly\n3. Remove unused extensions",
            "affected_asset": url,
        })

    return findings


async def _detect_cms(url: str) -> str | None:
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            resp = await client.get(url, headers={"User-Agent": "ShieldScan/1.0"})
            body = resp.text
            headers_str = str(resp.headers)

            for cms, signatures in CMS_SIGNATURES.items():
                if any(sig in body or sig in headers_str for sig in signatures):
                    return cms
    except Exception:
        pass
    return None


async def _wpscan_check(url: str, api_key: str) -> list[dict]:
    findings = []
    try:
        parsed = urlparse(url)
        domain = f"{parsed.scheme}://{parsed.netloc}"

        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.post(
                "https://wpscan.com/api/v3/wordpresses",
                json={"url": domain, "api_token": api_key, "enumerate": "vp,vt,u"},
                headers={"Authorization": f"Token token={api_key}", "Content-Type": "application/json"}
            )

            if resp.status_code == 401:
                return [{
                    "severity": "low",
                    "category": "cms",
                    "title": "WPScan API Key Invalid or Rate Limited",
                    "description": "The WPScan API key was rejected. Free tier allows 25 scans/day.",
                    "fix_steps": "Check your API key at wpscan.com",
                    "affected_asset": url,
                }]

            data = resp.json()
            vulns = data.get("vulnerabilities", [])

            for vuln in vulns:
                cvss = vuln.get("cvss", {}).get("score", 0)
                severity = "critical" if cvss >= 9 else "medium" if cvss >= 7 else "low"
                references = vuln.get("references", {}).get("url", [])
                ref_str = "\n".join(references[:3]) if references else "See WPScan database"

                findings.append({
                    "severity": severity,
                    "category": "cms_cve",
                    "title": f"WordPress Vulnerability: {vuln.get('title', 'Unknown')}",
                    "description": f"A known security vulnerability was found in your WordPress installation or one of its plugins/themes. CVSS Score: {cvss}/10",
                    "fix_steps": f"1. Update the affected component immediately\n2. Check if a patch is available at: {ref_str}\n3. If no patch exists, deactivate the plugin/theme until one is available",
                    "affected_asset": vuln.get("fixed_in", url),
                })

    except Exception as e:
        pass

    return findings
