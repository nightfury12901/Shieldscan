"""
Auth & JWT issue scanner.
Detects insecure JWT handling, missing token expiry, insecure session config.
"""
import re
from typing import Any


AUTH_PATTERNS = [
    (
        "JWT 'none' algorithm accepted",
        re.compile(r"(?i)algorithms?\s*[=:]\s*[\['\"]none[\]'\"]", re.MULTILINE),
        "critical", "jwt_none_alg",
        "Your code accepts the 'none' JWT algorithm, meaning tokens need no signature. Any attacker can forge a valid JWT token for any user without knowing any secret.",
        "1. Remove 'none' from your list of accepted JWT algorithms\n2. Use RS256 for production (asymmetric — more secure)\n3. Ensure your JWT library rejects unsigned tokens by default",
    ),
    (
        "Hardcoded JWT secret",
        re.compile(r"(?i)(jwt.?secret|secret.?key|signing.?key)\s*[=:]\s*['\"][^'\"]{4,}['\"]", re.MULTILINE),
        "critical", "hardcoded_secret",
        "Your JWT signing secret is hardcoded in the source code. Anyone who can read the code can forge valid authentication tokens for any user account.",
        "1. Move the JWT secret to an environment variable: process.env.JWT_SECRET or os.getenv('JWT_SECRET')\n2. Generate a secure random secret: openssl rand -base64 64\n3. Rotate the current secret — it is compromised",
    ),
    (
        "JWT missing expiry",
        re.compile(r"(?i)jwt\.sign\s*\([^)]+\)\s*(?!.*exp)", re.MULTILINE),
        "medium", "jwt_no_expiry",
        "JWT tokens are being created without an expiry time. Stolen tokens remain valid forever — there's no way to invalidate them.",
        "1. Always include an expiry: jwt.sign(payload, secret, { expiresIn: '1h' })\n2. Use short expiry times for access tokens (15–60 minutes)\n3. Use refresh tokens for long-lived sessions",
    ),
    (
        "Insecure session secret",
        re.compile(r"(?i)session\s*\([^)]*secret\s*:\s*['\"][^'\"]{1,20}['\"]", re.MULTILINE),
        "critical", "weak_session_secret",
        "A weak or short session secret was found. Short secrets can be brute-forced, allowing attackers to forge valid session cookies.",
        "1. Use a long random secret: crypto.randomBytes(64).toString('hex')\n2. Store it in an environment variable\n3. Rotate the secret and invalidate all existing sessions",
    ),
    (
        "Cookie without HttpOnly flag",
        re.compile(r"(?i)set.?cookie[^;]+(?!HttpOnly)", re.MULTILINE),
        "medium", "insecure_cookie",
        "Session cookies may be set without the HttpOnly flag. Without HttpOnly, JavaScript on your page can access cookies — attackers who inject JavaScript can steal all user sessions.",
        "1. Always set HttpOnly on authentication cookies: Set-Cookie: session=...; HttpOnly; Secure\n2. Also add the Secure flag to ensure cookies only sent over HTTPS",
    ),
    (
        "Password comparison timing attack",
        re.compile(r"(?i)(password|passwd|pwd)\s*==\s*|===\s*(password|passwd|pwd)", re.MULTILINE),
        "medium", "timing_attack",
        "Passwords are compared using regular equality (==). This is vulnerable to timing attacks where an attacker can measure response time differences to guess passwords character by character.",
        "1. Use a constant-time comparison function: hmac.compare_digest() in Python, timingSafeEqual in Node.js\n2. Better: don't compare passwords directly — hash them with bcrypt and compare hashes",
    ),
]


async def scan_auth_issues(files: list[dict]) -> list[dict]:
    findings = []
    seen_sigs = set()

    SKIP_DIRS = {"node_modules", ".git", "vendor", "dist", "build", "__pycache__"}
    SKIP_EXTS = {".min.js", ".map", ".png", ".jpg", ".gif", ".svg"}

    for file_obj in files:
        path = file_obj.get("path", "")
        content = file_obj.get("content", "")

        if any(f"/{skip}/" in f"/{path}" or path.startswith(f"{skip}/") for skip in SKIP_DIRS):
            continue
        if any(path.endswith(ext) for ext in SKIP_EXTS):
            continue

        lines = content.split("\n")

        for name, pattern, severity, category, description, fix_steps in AUTH_PATTERNS:
            for m in pattern.finditer(content):
                line_num = content[:m.start()].count("\n") + 1
                sig = f"{name}:{path}:{line_num}"
                if sig in seen_sigs:
                    continue
                seen_sigs.add(sig)

                start = max(0, line_num - 2)
                end = min(len(lines), line_num + 1)
                context = "\n".join(f"  {i+start+1}: {lines[i]}" for i in range(end - start))

                findings.append({
                    "severity": severity,
                    "category": category,
                    "title": f"Auth/JWT Issue: {name}",
                    "description": description,
                    "fix_steps": fix_steps,
                    "affected_asset": path,
                    "line_number": line_num,
                    "metadata": {"context": context},
                })

    return findings
