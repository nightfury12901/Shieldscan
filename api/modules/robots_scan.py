"""
robots.txt & sitemap.xml exposure scanner.
Detects admin paths, internal APIs, and staging paths accidentally exposed
in robots.txt Disallow rules or sitemap.xml URLs.
"""
import httpx
import re
from urllib.parse import urlparse


# Paths that look sensitive when they appear in robots.txt or sitemap.xml
SENSITIVE_PATH_PATTERNS = [
    re.compile(r"/(admin|administrator|wp-admin|backend|dashboard)", re.IGNORECASE),
    re.compile(r"/(api|rest|graphql|rpc|internal|private)", re.IGNORECASE),
    re.compile(r"/(debug|actuator|healthz|metrics|status|monitor)", re.IGNORECASE),
    re.compile(r"/(staging|dev|development|test|sandbox|qa)", re.IGNORECASE),
    re.compile(r"/\.env|/config|/setup|/install|/upgrade", re.IGNORECASE),
    re.compile(r"/(backup|dump|export|import|migrate)", re.IGNORECASE),
    re.compile(r"/(login|auth|oauth|sso|signin|signup|register)", re.IGNORECASE),
]


async def scan_robots(url: str) -> list[dict]:
    findings = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
        # ── robots.txt ─────────────────────────────────────────────────
        try:
            robots_resp = await client.get(
                f"{base}/robots.txt",
                headers={"User-Agent": "ShieldScan/1.0"},
            )
            if robots_resp.status_code == 200 and len(robots_resp.text) > 10:
                robots_text = robots_resp.text
                sensitive_found = []
                for line in robots_text.splitlines():
                    # Disallow: /some-path   OR   Allow: /some-path
                    if line.strip().lower().startswith(("disallow:", "allow:", "sitemap:")):
                        path_part = re.sub(r"^(disallow|allow|sitemap)\s*:", "", line, flags=re.IGNORECASE).strip()
                        for pattern in SENSITIVE_PATH_PATTERNS:
                            if pattern.search(path_part) and path_part not in sensitive_found:
                                sensitive_found.append(path_part)
                                break

                if sensitive_found:
                    findings.append({
                        "severity": "medium",
                        "category": "information_disclosure",
                        "title": "Sensitive Paths Exposed in robots.txt",
                        "description": (
                            f"Your robots.txt file lists {len(sensitive_found)} sensitive path(s) "
                            f"such as: {', '.join(sensitive_found[:5])}. "
                            "Although robots.txt is meant to guide search engines, it inadvertently "
                            "reveals internal paths to attackers who routinely check this file."
                        ),
                        "fix_steps": (
                            "1. Review your robots.txt and remove references to admin, API, debug, and internal paths\n"
                            "2. Security through obscurity (robots.txt) does NOT protect endpoints — add proper authentication\n"
                            "3. Consider using a generic robots.txt: Disallow: / for protected areas\n"
                            "4. Ensure all sensitive paths require authentication regardless"
                        ),
                        "affected_asset": f"{base}/robots.txt",
                    })

            elif robots_resp.status_code == 200 and "User-agent" in robots_resp.text:
                # robots.txt exists and is readable — note it
                pass

        except Exception:
            pass

        # ── sitemap.xml ────────────────────────────────────────────────
        try:
            sitemap_resp = await client.get(
                f"{base}/sitemap.xml",
                headers={"User-Agent": "ShieldScan/1.0"},
            )
            if sitemap_resp.status_code == 200:
                sitemap_text = sitemap_resp.text
                # Extract all <loc> URLs
                loc_urls = re.findall(r"<loc>(.*?)</loc>", sitemap_text, re.IGNORECASE)
                sensitive_sitemap = []
                for loc_url in loc_urls:
                    for pattern in SENSITIVE_PATH_PATTERNS:
                        if pattern.search(loc_url) and loc_url not in sensitive_sitemap:
                            sensitive_sitemap.append(loc_url)
                            break

                if sensitive_sitemap:
                    findings.append({
                        "severity": "low",
                        "category": "information_disclosure",
                        "title": "Sensitive URLs Indexed in sitemap.xml",
                        "description": (
                            f"Your sitemap.xml contains {len(sensitive_sitemap)} sensitive URL(s): "
                            f"{', '.join([u.split('/')[-1] for u in sensitive_sitemap[:3]])}. "
                            "Sitemaps are publicly crawled by search engines and attackers alike — "
                            "admin panels and API endpoints should not appear here."
                        ),
                        "fix_steps": (
                            "1. Remove admin, internal API, and auth URLs from your sitemap.xml\n"
                            "2. Only include public-facing, indexable content in sitemaps\n"
                            "3. Use your CMS or framework's sitemap generator with exclusion rules\n"
                            "4. Add these paths to your robots.txt Disallow rules"
                        ),
                        "affected_asset": f"{base}/sitemap.xml",
                    })

        except Exception:
            pass

    return findings
