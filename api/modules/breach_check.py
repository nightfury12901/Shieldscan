"""
LeakIX API — OSINT infrastructure leak check.
Checks if the domain has exposed databases, open services, or leaked .env files globally.
Free API, no key required.
"""
import asyncio
import httpx
from urllib.parse import urlparse


async def check_breach(url: str) -> list[dict]:
    findings = []
    parsed = urlparse(url)
    domain = parsed.netloc.split(":")[0] or parsed.path.split(":")[0]

    # Ignore IP addresses or localhost
    if domain in ("localhost", "127.0.0.1") or domain.replace(".", "").isnumeric():
        return findings

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"https://leakix.net/domain/{domain}",
                headers={"Accept": "application/json"}
            )
            
            if resp.status_code == 200:
                data = resp.json()
                services = data.get("Services", [])
                leaks = data.get("Leaks", [])
                
                # We analyze confirmed leaks (e.g., open ElasticSearch, exposed Git, SQL dumps)
                if leaks:
                    leak_names = list(set([leak.get("plugin", "Unknown") for leak in leaks]))
                    findings.append({
                        "severity": "critical",
                        "category": "breach_found",
                        "title": f"Critical Infrastructure Leaks Detected ({len(leaks)})",
                        "description": f"OSINT indexing via LeakIX shows {len(leaks)} exposed services or datasets leaking data on your domain's infrastructure. Identified vectors: {', '.join(leak_names)}. This means attackers can likely download your database or source code directly.",
                        "fix_steps": "1. Review all open ports and databases facing the internet immediately\n2. Put exposed databases (Elasticsearch, Redis, MySQL) behind a firewall or VPN limit\n3. Check your webroot for exposed .env or .git folders\n4. Search your domain on leakix.net for granular IPs",
                        "affected_asset": f"{domain}",
                    })
                elif services and len(services) > 5:
                    findings.append({
                        "severity": "medium",
                        "category": "breach",
                        "title": f"High Number of Exposed Services ({len(services)})",
                        "description": f"LeakIX OSINT engines have indexed {len(services)} distinct services running openly on this domain's IPs. While not confirmed leaks, exposing too many management ports increases attack surface.",
                        "fix_steps": "1. Implement a Zero Trust architecture or VPN for management interfaces\n2. Block public internet access to internal tools\n3. Review edge firewall rules",
                        "affected_asset": domain,
                    })

    except Exception:
        pass

    return findings
