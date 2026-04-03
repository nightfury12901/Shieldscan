"""
DNS / SPF / DMARC scanner.
Also runs India-specific checks: DPDPA privacy policy, HTTP form collection.
"""
import asyncio
import re
from urllib.parse import urlparse
from typing import Any

import dns.resolver
import dns.asyncresolver
import httpx


async def scan_dns(url: str) -> list[dict]:
    findings = []
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    domain = _extract_root_domain(hostname)

    tasks = [
        _check_spf(domain),
        _check_dmarc(domain),
        _check_mx(domain),
        _check_dpdpa(url),
        _check_http_forms(url),
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, list):
            findings.extend(r)

    return findings


def _extract_root_domain(hostname: str) -> str:
    parts = hostname.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname


async def _check_spf(domain: str) -> list[dict]:
    findings = []
    try:
        resolver = dns.asyncresolver.Resolver()
        answers = await resolver.resolve(domain, "TXT")
        spf_records = [r.to_text() for r in answers if "v=spf1" in r.to_text()]

        if not spf_records:
            findings.append({
                "severity": "medium",
                "category": "no_spf",
                "title": "No SPF Record — Email Spoofing Risk",
                "description": "Your domain has no SPF record. This means anyone can send emails that appear to come from your business. Attackers can impersonate you to scam your customers.",
                "fix_steps": "1. Log in to your domain registrar's DNS settings\n2. Add a TXT record: v=spf1 include:_spf.google.com ~all (replace with your email provider)\n3. Ask your email provider for the correct SPF record to use",
                "affected_asset": f"{domain} (TXT record)",
            })
        else:
            spf = spf_records[0]
            if "+all" in spf:
                findings.append({
                    "severity": "critical",
                    "category": "no_spf",
                    "title": "SPF Record Allows All Senders (+all)",
                    "description": "Your SPF record uses '+all' which allows anyone in the world to send emails as your domain. This completely defeats the purpose of having SPF.",
                    "fix_steps": "1. Change '+all' to '~all' (soft fail) or '-all' (hard fail)\n2. Recommended: v=spf1 include:your-mail-provider.com -all",
                    "affected_asset": f"{domain}: {spf}",
                })
    except dns.resolver.NXDOMAIN:
        pass
    except Exception:
        pass
    return findings


async def _check_dmarc(domain: str) -> list[dict]:
    findings = []
    try:
        resolver = dns.asyncresolver.Resolver()
        try:
            answers = await resolver.resolve(f"_dmarc.{domain}", "TXT")
            dmarc_records = [r.to_text() for r in answers if "v=DMARC1" in r.to_text()]

            if not dmarc_records:
                raise dns.resolver.NoAnswer()

            dmarc = dmarc_records[0]
            policy_match = re.search(r"p=(\w+)", dmarc)
            policy = policy_match.group(1).lower() if policy_match else "none"

            if policy == "none":
                findings.append({
                    "severity": "medium",
                    "category": "dmarc_weak",
                    "title": "DMARC Policy Set to 'None' — Emails Not Protected",
                    "description": "Your DMARC record exists but does nothing (p=none). Attackers can still send phishing emails that appear to come from your domain to trick your customers.",
                    "fix_steps": "1. Change your DMARC policy from 'none' to 'quarantine' (puts fake emails in spam)\n2. Eventually upgrade to 'reject' (blocks fake emails completely)\n3. Example: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com",
                    "affected_asset": f"_dmarc.{domain}: {dmarc}",
                })
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            findings.append({
                "severity": "medium",
                "category": "no_dmarc",
                "title": "No DMARC Record — Email Impersonation Risk",
                "description": "Your domain has no DMARC record. Without this, email providers have no instructions for what to do with fake emails pretending to be from you. Criminals can send phishing emails as your business.",
                "fix_steps": "1. Add a DMARC TXT record at _dmarc.yourdomain.com\n2. Start with: v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com\n3. After monitoring, upgrade to p=quarantine then p=reject\n4. Use a free tool like dmarcian.com to check your record",
                "affected_asset": f"_dmarc.{domain}",
            })
    except Exception:
        pass
    return findings


async def _check_mx(domain: str) -> list[dict]:
    """Check for subdomain takeover signals via dangling CNAME records."""
    findings = []
    try:
        resolver = dns.asyncresolver.Resolver()
        # Check for common subdomains that might be dangling
        common_subs = ["www", "mail", "blog", "shop", "store", "app", "api"]
        for sub in common_subs:
            full = f"{sub}.{domain}"
            try:
                cname_answers = await resolver.resolve(full, "CNAME")
                for cname in cname_answers:
                    cname_target = str(cname.target).rstrip(".")
                    # Check if CNAME target resolves
                    try:
                        await resolver.resolve(cname_target, "A")
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                        findings.append({
                            "severity": "critical",
                            "category": "subdomain_takeover",
                            "title": f"Potential Subdomain Takeover: {full}",
                            "description": f"The subdomain {full} points to {cname_target} which doesn't exist. An attacker could register this service and take over your subdomain, serving malicious content under your brand.",
                            "fix_steps": f"1. Either delete the DNS record for {full} if it's no longer needed\n2. Or re-register the service {cname_target} is supposed to point to\n3. Check all your DNS records regularly for dangling references",
                            "affected_asset": f"{full} → {cname_target} (NXDOMAIN)",
                        })
            except Exception:
                pass
    except Exception:
        pass
    return findings


async def _check_dpdpa(url: str) -> list[dict]:
    """India DPDPA: check if site has a privacy policy page."""
    findings = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    privacy_paths = ["/privacy-policy", "/privacy", "/legal/privacy", "/policies/privacy"]

    try:
        async with httpx.AsyncClient(timeout=8, follow_redirects=True) as client:
            found = False
            for path in privacy_paths:
                try:
                    resp = await client.get(f"{base}{path}")
                    if resp.status_code == 200 and len(resp.text) > 500:
                        found = True
                        break
                except Exception:
                    pass

            if not found:
                findings.append({
                    "severity": "medium",
                    "category": "dpdpa",
                    "title": "No Privacy Policy Page Found (DPDPA Compliance)",
                    "description": "India's Digital Personal Data Protection Act (DPDPA) requires businesses that collect personal data to publish a clear privacy policy. No privacy policy page was found on your site.",
                    "fix_steps": "1. Create a privacy policy page at /privacy-policy\n2. The policy must explain: what data you collect, why you collect it, and how users can request deletion\n3. Link to it from your footer and any data collection forms\n4. Consider using a free privacy policy generator to get started",
                    "affected_asset": base,
                })
    except Exception:
        pass
    return findings


async def _check_http_forms(url: str) -> list[dict]:
    """India check: forms collecting data without HTTPS."""
    findings = []
    if url.startswith("https://"):
        return findings  # HTTPS is fine

    try:
        async with httpx.AsyncClient(timeout=8, follow_redirects=False) as client:
            resp = await client.get(url)
            if "<form" in resp.text.lower() and ("input" in resp.text.lower()):
                findings.append({
                    "severity": "critical",
                    "category": "http_form",
                    "title": "Form Collecting Data Over Unencrypted HTTP",
                    "description": "Your website collects user information (via an HTML form) over plain HTTP, not HTTPS. Every piece of data your customers submit — including names, emails, and passwords — travels across the internet in plain text and can be intercepted.",
                    "fix_steps": "1. Get an SSL certificate immediately (free via Let's Encrypt)\n2. Serve your entire site over HTTPS\n3. Redirect all HTTP traffic to HTTPS\n4. This is also required for DPDPA compliance in India",
                    "affected_asset": url,
                })
    except Exception:
        pass
    return findings
