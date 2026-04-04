"""
Third-Party JavaScript Supply Chain scanner.
Audits external scripts loaded by the page for missing SRI hashes and
flags unknown/suspicious CDN domains.
"""
import httpx
import re
from urllib.parse import urlparse


# Well-known, trusted CDN/script domains
TRUSTED_DOMAINS = {
    "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com",
    "ajax.googleapis.com", "fonts.googleapis.com", "fonts.gstatic.com",
    "code.jquery.com", "maxcdn.bootstrapcdn.com", "stackpath.bootstrapcdn.com",
    "cdn.ampproject.org", "static.cloudflareinsights.com",
    "www.google-analytics.com", "www.googletagmanager.com",
    "connect.facebook.net", "platform.twitter.com",
    "js.stripe.com", "js.braintreegateway.com", "checkout.razorpay.com",
    "checkout.stripe.com", "static.hotjar.com", "script.hotjar.com",
    "cdn.segment.com", "js.intercomcdn.com", "widget.intercom.io",
    "cdn.lr-ingest.io",  # LogRocket
}

# Patterns that look like potentially malicious or unusual origin domains
SUSPICIOUS_PATTERNS = [
    re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"),  # IP address as host
    re.compile(r"\.(tk|ml|ga|cf|pw|top|xyz|click|download|loan)$", re.IGNORECASE),
    re.compile(r"(free|hack|crack|warez|nulled)", re.IGNORECASE),
]


async def scan_supply_chain(url: str) -> list[dict]:
    findings = []
    try:
        async with httpx.AsyncClient(timeout=12, follow_redirects=True) as client:
            resp = await client.get(url, headers={
                "User-Agent": "Mozilla/5.0 (compatible; ShieldScan/1.0)"
            })
            html = resp.text

        # Extract all <script src="..."> tags
        script_tags = re.findall(
            r'<script[^>]*\bsrc=["\']([^"\']+)["\'][^>]*>',
            html, re.IGNORECASE
        )

        external_scripts = []
        for src in script_tags:
            if src.startswith("http://") or src.startswith("https://") or src.startswith("//"):
                external_scripts.append(src)

        no_sri = []
        suspicious = []

        # Full tag extraction for SRI check
        script_full_tags = re.findall(
            r'<script[^>]*\bsrc=["\']([^"\']+)["\'][^>]*(?:integrity=["\']([^"\']*)["\'])?[^>]*>',
            html, re.IGNORECASE
        )

        # Build set of external scripts that DO have integrity attributes
        has_integrity = set()
        for m in re.finditer(
            r'<script[^>]*integrity=["\'][^"\']+["\'][^>]*src=["\']([^"\']+)["\']|'
            r'<script[^>]*src=["\']([^"\']+)["\'][^>]*integrity=["\'][^"\']+["\']',
            html, re.IGNORECASE
        ):
            src = m.group(1) or m.group(2)
            if src:
                has_integrity.add(src.strip())

        page_hostname = urlparse(url).hostname or ""

        for src in external_scripts:
            src_hostname = urlparse(src).hostname or urlparse(f"https:{src}").hostname or ""

            # Skip same-origin scripts
            if src_hostname == page_hostname:
                continue

            # Check for suspicious origin
            is_suspicious = any(p.search(src_hostname) for p in SUSPICIOUS_PATTERNS)
            if is_suspicious:
                suspicious.append(src)

            # Check for missing SRI
            if src not in has_integrity and src_hostname not in TRUSTED_DOMAINS:
                no_sri.append(src)

        if suspicious:
            for src in suspicious[:5]:
                findings.append({
                    "severity": "critical",
                    "category": "supply_chain",
                    "title": f"Suspicious Third-Party Script Detected",
                    "description": (
                        f"Your page loads a script from a suspicious domain: {src}. "
                        "Magecart and supply chain attacks work by injecting malicious JavaScript "
                        "via third-party scripts to steal credit card numbers and customer data."
                    ),
                    "fix_steps": (
                        "1. Urgently review what this script does and whether it should be loaded\n"
                        "2. Remove any scripts from unknown or untrusted domains immediately\n"
                        "3. If required, self-host the script instead of relying on external CDN\n"
                        "4. Add Subresource Integrity (integrity='sha384-...') to allow-listed scripts"
                    ),
                    "affected_asset": src,
                })

        if no_sri:
            # Group into one finding to avoid noise
            findings.append({
                "severity": "medium",
                "category": "supply_chain",
                "title": "External Scripts Missing Subresource Integrity (SRI)",
                "description": (
                    f"Found {len(no_sri)} external script(s) loaded without Subresource Integrity hashes. "
                    "If a CDN is compromised, attackers can silently modify these scripts to steal "
                    "customer data (Magecart-style attack). Affected scripts: "
                    f"{', '.join([s.split('?')[0][-60:] for s in no_sri[:3]])}"
                ),
                "fix_steps": (
                    "1. Generate SRI hashes for all external scripts at https://www.srihash.org\n"
                    "2. Add integrity and crossorigin attributes:\n"
                    "   <script src='...' integrity='sha384-...' crossorigin='anonymous'>\n"
                    "3. Pin to specific versions (not @latest) to prevent unexpected updates\n"
                    "4. Consider self-hosting critical third-party libraries"
                ),
                "affected_asset": url,
            })

    except Exception:
        pass

    return findings
