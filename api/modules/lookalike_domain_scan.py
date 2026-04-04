"""
Lookalike Domain / Competitor Monitoring scanner.
Generates typosquatting variants of the target domain and checks which
are registered — a classic technique used in phishing attacks targeting
a business's customers.
"""
import asyncio
import dns.asyncresolver
import dns.resolver
from urllib.parse import urlparse
import itertools


def _extract_root_domain(hostname: str) -> tuple[str, str]:
    """Returns (name, tld) e.g. ('myshop', 'com') from 'myshop.com'."""
    parts = hostname.split(".")
    if len(parts) >= 2:
        return ".".join(parts[:-1]), parts[-1]
    return hostname, "com"


def _generate_typosquats(name: str, tld: str) -> list[str]:
    """Generate a focused set of lookalike domain variants."""
    variants: set[str] = set()

    # Common phishing suffixes
    phishing_suffixes = [
        "-secure", "-login", "-verify", "-support", "-help",
        "-official", "-store", "-shop", "-app", "-portal",
        "-payments", "-account", "-auth", "secure", "login",
        "-deals", "-sale", "-offers",
    ]
    for suffix in phishing_suffixes:
        variants.add(f"{name}{suffix}.{tld}")
        variants.add(f"{name}{suffix}.com")

    # Different TLDs
    alt_tlds = ["net", "org", "co", "io", "biz", "info", "shop", "store", "online", "site"]
    for alt_tld in alt_tlds:
        if alt_tld != tld:
            variants.add(f"{name}.{alt_tld}")

    # Character substitutions (common typos)
    char_subs = {"a": ["4"], "e": ["3"], "i": ["1", "l"], "o": ["0"], "s": ["5"]}
    for i, char in enumerate(name):
        if char in char_subs:
            for sub in char_subs[char]:
                variant_name = name[:i] + sub + name[i+1:]
                variants.add(f"{variant_name}.{tld}")

    # Double letters (fat-finger typos)
    for i, char in enumerate(name):
        doubled = name[:i] + char + char + name[i:]
        variants.add(f"{doubled}.{tld}")

    # Missing letter (adjacent key dropped)
    for i in range(len(name)):
        missing = name[:i] + name[i+1:]
        if len(missing) > 2:
            variants.add(f"{missing}.{tld}")

    # Limit to avoid massive DNS load
    return list(variants)[:60]


async def _is_domain_registered(domain: str) -> bool:
    """Return True if domain resolves (i.e., is registered and has DNS)."""
    try:
        resolver = dns.asyncresolver.Resolver()
        # Try A record first
        await resolver.resolve(domain, "A", lifetime=3)
        return True
    except dns.resolver.NXDOMAIN:
        return False
    except dns.resolver.NoAnswer:
        # Has NS records but no A record — still registered
        return True
    except Exception:
        return False


async def scan_lookalike_domains(url: str) -> list[dict]:
    findings = []
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        if not hostname:
            return findings

        name, tld = _extract_root_domain(hostname)

        # Don't run on IPs or very short names
        if len(name) < 3 or name.replace(".", "").isdigit():
            return findings

        variants = _generate_typosquats(name, tld)

        # Check in batches of 15 concurrently
        registered: list[str] = []
        batch_size = 15
        for i in range(0, len(variants), batch_size):
            batch = variants[i:i + batch_size]
            results = await asyncio.gather(
                *[_is_domain_registered(d) for d in batch],
                return_exceptions=True,
            )
            for domain, result in zip(batch, results):
                if result is True:
                    registered.append(domain)
            # Small pause between batches
            await asyncio.sleep(0.2)

        # Filter out the target domain itself just in case
        root_domain = f"{name}.{tld}"
        registered = [d for d in registered if d != root_domain and not d.endswith(f".{hostname}")]

        if registered:
            # Flag the most dangerous-looking ones first
            priority = [d for d in registered if any(
                kw in d for kw in ["-secure", "-login", "-verify", "-support", "-official", "-store"]
            )]
            rest = [d for d in registered if d not in priority]
            ordered = priority + rest

            findings.append({
                "severity": "critical" if priority else "medium",
                "category": "lookalike_domain",
                "title": f"Lookalike Domains Registered — Phishing Risk",
                "description": (
                    f"Found {len(registered)} domain(s) that are visually similar to '{root_domain}' "
                    "and are currently registered and resolving. Attackers register these to impersonate "
                    "your business in phishing emails and fake login pages targeting your customers. "
                    f"Detected domains include: {', '.join(ordered[:5])}"
                ),
                "fix_steps": (
                    "1. Register the most dangerous lookalike domains yourself to prevent future abuse\n"
                    "2. File abuse reports via ICANN if domains are currently being used to phish customers\n"
                    "3. Set up DMARC (p=reject) so your email cannot be spoofed from these lookalikes\n"
                    "4. Alert your customers via email about potential phishing attempts\n"
                    "5. Monitor with anti-phishing services like Bolster, PhishLabs, or Cloudflare Radar\n"
                    "6. Use your domain registrar's brand protection features"
                ),
                "affected_asset": root_domain,
                "metadata": {"lookalike_domains": ordered[:20]},
            })

    except Exception:
        pass

    return findings
