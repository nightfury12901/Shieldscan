"""
Rate limiting / login bruteforce scanner.
Sends rapid requests to common auth endpoints and checks whether
the server enforces rate limiting (429, Retry-After, CAPTCHA, etc.)
"""
import asyncio
import httpx
from urllib.parse import urlparse


AUTH_PATHS = [
    "/login",
    "/signin",
    "/admin",
    "/admin/login",
    "/api/auth",
    "/api/login",
    "/wp-login.php",
    "/user/login",
    "/account/login",
]


async def scan_rate_limiting(url: str) -> list[dict]:
    findings = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    async with httpx.AsyncClient(timeout=8, follow_redirects=False) as client:
        for path in AUTH_PATHS:
            target = f"{base}{path}"
            try:
                # First check if endpoint exists (respond with anything other than 404)
                probe = await client.get(target, headers={"User-Agent": "ShieldScan/1.0"})
                if probe.status_code == 404:
                    continue

                # Fire 12 rapid POST requests with fake credentials
                tasks = [
                    client.post(
                        target,
                        data={"username": "admin", "password": f"test{i}"},
                        headers={"User-Agent": "ShieldScan/1.0"},
                    )
                    for i in range(12)
                ]
                responses = await asyncio.gather(*tasks, return_exceptions=True)

                rate_limited = False
                for r in responses:
                    if isinstance(r, Exception):
                        continue
                    # 429 Too Many Requests, 503 Service Unavailable, or Retry-After header
                    if r.status_code == 429:
                        rate_limited = True
                        break
                    if "retry-after" in r.headers:
                        rate_limited = True
                        break
                    if "x-ratelimit-limit" in r.headers:
                        rate_limited = True
                        break
                    # Check for CAPTCHA responses
                    body_lower = r.text.lower()
                    if "captcha" in body_lower or "recaptcha" in body_lower or "hcaptcha" in body_lower:
                        rate_limited = True
                        break

                if not rate_limited:
                    findings.append({
                        "severity": "critical",
                        "category": "rate_limiting",
                        "title": f"No Rate Limiting on Login Endpoint: {path}",
                        "description": (
                            f"The endpoint '{target}' accepted 12 rapid consecutive login attempts "
                            "without triggering any rate limiting, lockout, or CAPTCHA. "
                            "This means an attacker can run automated password-guessing attacks "
                            "(credential stuffing, brute force) against your users' accounts indefinitely."
                        ),
                        "fix_steps": (
                            f"1. Implement rate limiting on {path}: max 5 failed attempts per IP per minute\n"
                            "2. After 10 failed attempts, temporarily lock the account or require CAPTCHA\n"
                            "3. Use libraries like express-rate-limit (Node.js), Rack::Attack (Rails), or slowapi (FastAPI)\n"
                            "4. Add CAPTCHA (reCAPTCHA v3 or hCaptcha) for suspicious traffic patterns\n"
                            "5. Monitor failed login attempts and alert on spikes"
                        ),
                        "affected_asset": target,
                    })
                    # Only report the first unprotected endpoint to avoid noise
                    break

            except Exception:
                continue

    return findings
