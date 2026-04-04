"""
Cookie Security Flags scanner.
Checks Set-Cookie headers for missing HttpOnly, Secure, and SameSite flags.
"""
import httpx
from urllib.parse import urlparse


async def scan_cookies(url: str) -> list[dict]:
    findings = []
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            resp = await client.get(url, headers={"User-Agent": "ShieldScan/1.0"})

            # httpx exposes raw Set-Cookie headers via resp.headers.get_list
            raw_cookies: list[str] = []
            for k, v in resp.headers.multi_items():
                if k.lower() == "set-cookie":
                    raw_cookies.append(v)

            if not raw_cookies:
                return findings

            for cookie_str in raw_cookies:
                parts_lower = cookie_str.lower()
                # Extract cookie name (first part before =)
                cookie_name = cookie_str.split("=")[0].strip() or "unknown"

                if "httponly" not in parts_lower:
                    findings.append({
                        "severity": "critical",
                        "category": "cookie_security",
                        "title": f"Cookie Missing HttpOnly Flag: {cookie_name}",
                        "description": (
                            f"The cookie '{cookie_name}' does not have the HttpOnly flag set. "
                            "This means JavaScript running on the page (including injected malicious scripts) "
                            "can read this cookie, enabling session hijacking attacks via XSS."
                        ),
                        "fix_steps": (
                            f"1. Add the HttpOnly flag to the Set-Cookie header for '{cookie_name}'\n"
                            "2. Example: Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict\n"
                            "3. In most frameworks, there's a setting like cookie_httponly=True"
                        ),
                        "affected_asset": f"Set-Cookie: {cookie_name}",
                    })

                if "secure" not in parts_lower:
                    findings.append({
                        "severity": "medium",
                        "category": "cookie_security",
                        "title": f"Cookie Missing Secure Flag: {cookie_name}",
                        "description": (
                            f"The cookie '{cookie_name}' does not have the Secure flag. "
                            "This means the cookie may be transmitted over unencrypted HTTP connections, "
                            "exposing it to interception (man-in-the-middle attacks)."
                        ),
                        "fix_steps": (
                            f"1. Add the Secure flag to ensure '{cookie_name}' is only sent over HTTPS\n"
                            "2. Example: Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict\n"
                            "3. Also ensure your entire site is served over HTTPS"
                        ),
                        "affected_asset": f"Set-Cookie: {cookie_name}",
                    })

                if "samesite" not in parts_lower:
                    findings.append({
                        "severity": "medium",
                        "category": "cookie_security",
                        "title": f"Cookie Missing SameSite Flag: {cookie_name}",
                        "description": (
                            f"The cookie '{cookie_name}' has no SameSite attribute. "
                            "Without this flag, the cookie is sent with cross-site requests, "
                            "enabling Cross-Site Request Forgery (CSRF) attacks where malicious websites "
                            "can perform actions on behalf of logged-in users."
                        ),
                        "fix_steps": (
                            f"1. Add SameSite=Strict or SameSite=Lax to '{cookie_name}'\n"
                            "2. SameSite=Strict: cookie never sent cross-site (most secure)\n"
                            "3. SameSite=Lax: cookie sent only for GET requests from links (good balance)\n"
                            "4. Example: Set-Cookie: session=abc; HttpOnly; Secure; SameSite=Strict"
                        ),
                        "affected_asset": f"Set-Cookie: {cookie_name}",
                    })

    except Exception as e:
        pass  # Silently skip — cookie scan is non-critical

    return findings
