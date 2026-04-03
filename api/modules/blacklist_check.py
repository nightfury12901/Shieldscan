"""
Google Safe Browsing API — blacklist/malware/phishing check.
"""
import os
import asyncio
import httpx
from urllib.parse import urlparse


async def check_blacklist(url: str) -> list[dict]:
    findings = []
    api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
    if not api_key:
        return [{
            "severity": "low",
            "category": "blacklist",
            "title": "Blacklist Check Skipped (No API Key)",
            "description": "Google Safe Browsing API key not configured.",
            "fix_steps": "Add GOOGLE_SAFE_BROWSING_API_KEY to environment variables.",
            "affected_asset": url,
        }]

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
                json={
                    "client": {"clientId": "shieldscan", "clientVersion": "1.0"},
                    "threatInfo": {
                        "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": url}],
                    }
                }
            )
            data = resp.json()
            matches = data.get("matches", [])

            for match in matches:
                threat_type = match.get("threatType", "UNKNOWN")
                threat_name = {
                    "MALWARE": "Malware Distribution",
                    "SOCIAL_ENGINEERING": "Phishing / Social Engineering",
                    "UNWANTED_SOFTWARE": "Unwanted Software",
                    "POTENTIALLY_HARMFUL_APPLICATION": "Potentially Harmful Application",
                }.get(threat_type, threat_type)

                findings.append({
                    "severity": "critical",
                    "category": "blacklisted",
                    "title": f"Domain Flagged by Google: {threat_name}",
                    "description": f"Google Safe Browsing has flagged your website as a source of {threat_name.lower()}. Chrome, Firefox, and Safari show a 'Dangerous Site' warning to all visitors. Your site may have been hacked.",
                    "fix_steps": "1. Scan your website files for malware using a tool like Sucuri SiteCheck\n2. Remove any infected files\n3. Update all software (CMS, plugins, themes)\n4. Change all server and admin passwords\n5. After cleanup, request a Google review at: https://search.google.com/search-console/security-issues\n6. This usually takes 1-3 days to be removed from the blacklist",
                    "affected_asset": url,
                })

    except Exception:
        pass

    return findings
