"""
NVD CVE Lookup — matches software/version to known CVEs.
Used by both URL scan (server headers) and code scan (dependency files).
"""
import os
import asyncio
import re
import httpx
from urllib.parse import urlparse


NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


async def lookup_cves(url: str) -> list[dict]:
    """For URL scans: extract server software from headers and look up CVEs."""
    findings = []
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            resp = await client.get(url, headers={"User-Agent": "ShieldScan/1.0"})
            server = resp.headers.get("server", "")
            x_powered = resp.headers.get("x-powered-by", "")

            software_list = []
            if server:
                software_list.append(server)
            if x_powered:
                software_list.append(x_powered)

            for software in software_list:
                cve_findings = await _query_nvd(software)
                findings.extend(cve_findings)

    except Exception:
        pass
    return findings


async def lookup_cves_for_packages(packages: list[dict]) -> list[dict]:
    """For code scans: look up CVEs for a list of {name, version} packages."""
    findings = []
    # Batch queries with rate limiting (NVD allows ~5 req/sec without key, 50 with key)
    api_key = os.getenv("NVD_API_KEY", "")
    delay = 0.2 if api_key else 0.6

    for pkg in packages[:30]:  # Limit to 30 packages per scan
        name = pkg.get("name", "")
        version = pkg.get("version", "")
        if name:
            cve_findings = await _query_nvd(f"{name} {version}".strip(), name, version)
            findings.extend(cve_findings)
            await asyncio.sleep(delay)

    return findings


async def _query_nvd(keyword: str, pkg_name: str = "", pkg_version: str = "") -> list[dict]:
    findings = []
    api_key = os.getenv("NVD_API_KEY", "")
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                NVD_BASE,
                params={"keywordSearch": keyword, "resultsPerPage": 5},
                headers=headers,
            )
            if resp.status_code != 200:
                return []

            data = resp.json()
            vulns = data.get("vulnerabilities", [])

            for item in vulns:
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")
                descriptions = cve.get("descriptions", [])
                description = next((d["value"] for d in descriptions if d["lang"] == "en"), "")

                metrics = cve.get("metrics", {})
                cvss_score = 0.0
                cvss_version = ""
                for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if metric_key in metrics and metrics[metric_key]:
                        cvss_score = metrics[metric_key][0].get("cvssData", {}).get("baseScore", 0.0)
                        cvss_version = metric_key
                        break

                if cvss_score < 5.0:
                    continue  # Skip low-severity CVEs

                severity = "critical" if cvss_score >= 9.0 else "medium" if cvss_score >= 7.0 else "low"

                asset = pkg_name if pkg_name else keyword
                if pkg_version:
                    asset = f"{pkg_name}@{pkg_version}"

                findings.append({
                    "severity": severity,
                    "category": "vulnerable_dependency" if pkg_name else ("cve_critical" if cvss_score >= 9 else "cve_high"),
                    "title": f"{cve_id}: Known Vulnerability in {asset} (CVSS {cvss_score})",
                    "description": f"A known security vulnerability ({cve_id}) was found in '{asset}'. {description[:300]}",
                    "fix_steps": f"1. Update {asset} to the latest version immediately\n2. Check {cve_id} details at: https://nvd.nist.gov/vuln/detail/{cve_id}\n3. If no update is available, look for a workaround in the CVE advisory",
                    "affected_asset": asset,
                    "compliance": ["SOC2 CC7.1", "PCI-DSS Req 6.2"],
                })

    except Exception:
        pass

    return findings
