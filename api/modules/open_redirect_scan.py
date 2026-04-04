"""
Open Redirect Detection scanner.
Probes common redirect parameters with external URLs to detect
unvalidated redirect vulnerabilities used heavily in phishing attacks.
"""
import asyncio
import httpx
from urllib.parse import urlparse, urlencode


# Common redirect parameter names
REDIRECT_PARAMS = [
    "redirect", "redirect_uri", "redirect_url", "redirectUrl", "redirectUri",
    "next", "return", "return_url", "returnUrl", "returnto",
    "url", "target", "dest", "destination", "go", "goto",
    "continue", "forward", "link", "checkout_url",
]

# Common paths that typically have redirect parameters
REDIRECT_PATHS = [
    "/login", "/signin", "/auth/login", "/account/login", "/user/login",
    "/logout", "/signout",
    "/auth/callback", "/oauth/callback",
    "/api/auth", "/api/login",
    "/checkout", "/cart",
    "",  # Root URL
]

# External URL to inject
CANARY_URL = "https://evil.shieldscan-test.example.com"


async def scan_open_redirects(url: str) -> list[dict]:
    findings = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    seen_params: set[str] = set()

    async with httpx.AsyncClient(
        timeout=8,
        follow_redirects=False,
        headers={"User-Agent": "ShieldScan/1.0"},
    ) as client:
        for path in REDIRECT_PATHS:
            for param in REDIRECT_PARAMS:
                if param in seen_params:
                    continue

                test_url = f"{base}{path}?{param}={CANARY_URL}"
                try:
                    resp = await client.get(test_url)
                    # Check if response redirects to our canary URL
                    location = resp.headers.get("location", "")
                    if (
                        resp.status_code in (301, 302, 303, 307, 308)
                        and CANARY_URL in location
                    ):
                        seen_params.add(param)
                        findings.append({
                            "severity": "critical",
                            "category": "open_redirect",
                            "title": f"Open Redirect Vulnerability: ?{param}= parameter",
                            "description": (
                                f"The endpoint '{base}{path}?{param}=URL' redirects users to any "
                                "URL without validation. Attackers exploit this to craft phishing links "
                                "that appear to come from your trusted domain, tricking users into visiting "
                                "malicious sites. Example attack: "
                                f"{base}{path}?{param}=https://fake-bank.com/login"
                            ),
                            "fix_steps": (
                                f"1. Validate the '{param}' parameter against an allowlist of trusted domains\n"
                                "2. Only allow relative URLs (starting with /) for redirects\n"
                                "3. Example validation: if not url.startswith('/') or url.startswith('//'): abort(400)\n"
                                "4. Never redirect to URLs containing :// unless the domain is in your allowlist\n"
                                "5. Use a signed token approach for redirect URLs from email links"
                            ),
                            "affected_asset": f"{base}{path}?{param}=",
                        })
                        break  # One finding per path is enough
                except Exception:
                    continue

            # Avoid hammering the server — small delay between paths
            await asyncio.sleep(0.1)

    return findings
