"""
SSL/TLS scanner.
Primary: Python stdlib ssl + socket (works everywhere).
Fallback: sslyze (optional, imported only if available).
"""
import asyncio
import ssl
import socket
import datetime
from urllib.parse import urlparse
from typing import Any


async def scan_ssl(url: str) -> list[dict]:
    findings = []
    parsed = urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    if parsed.scheme != "https":
        findings.append({
            "severity": "critical",
            "category": "ssl",
            "title": "Website Not Using HTTPS",
            "description": "Your website is served over plain HTTP. All data between your customers and your site is unencrypted and can be intercepted.",
            "fix_steps": "1. Get an SSL certificate (free via Let's Encrypt: https://letsencrypt.org)\n2. Configure your web server to serve on port 443\n3. Redirect all HTTP traffic to HTTPS",
            "affected_asset": url,
        })
        return findings

    loop = asyncio.get_event_loop()
    try:
        cert_info = await loop.run_in_executor(None, _check_ssl_stdlib, hostname, port)
        findings.extend(_analyze_cert(cert_info, hostname))
    except Exception as e:
        findings.append({
            "severity": "critical",
            "category": "ssl",
            "title": "SSL Certificate Error",
            "description": f"Could not verify your site's SSL certificate: {str(e)}. This means browsers will show a security warning to all your visitors.",
            "fix_steps": "1. Check your SSL certificate is installed correctly\n2. Ensure it hasn't expired\n3. Verify certificate is issued for the correct domain name",
            "affected_asset": hostname,
        })

    # Optionally try sslyze for deeper checks
    try:
        import importlib
        sslyze = importlib.import_module("sslyze")
        extra = await loop.run_in_executor(None, _check_sslyze, hostname, port)
        findings.extend(extra)
    except (ImportError, ModuleNotFoundError):
        pass  # sslyze not installed — stdlib check is sufficient
    except Exception:
        pass  # sslyze check failed — not fatal

    return findings


def _check_ssl_stdlib(hostname: str, port: int) -> dict:
    ctx = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()
            cipher = ssock.cipher()
            version = ssock.version()
            return {"cert": cert, "cipher": cipher, "tls_version": version}


def _analyze_cert(info: dict, hostname: str) -> list[dict]:
    findings = []
    cert = info.get("cert", {})
    tls_version = info.get("tls_version", "")

    # Expiry check
    not_after = cert.get("notAfter", "")
    if not_after:
        try:
            expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry - datetime.datetime.utcnow()).days

            if days_left < 0:
                findings.append({
                    "severity": "critical",
                    "category": "ssl_expired",
                    "title": "SSL Certificate Has Expired",
                    "description": f"Your SSL certificate expired {abs(days_left)} days ago. Every visitor to your site sees a security warning. This destroys customer trust and Google rankings.",
                    "fix_steps": "1. Renew your SSL certificate immediately\n2. If using Let's Encrypt, run: certbot renew\n3. Contact your hosting provider if you need help",
                    "affected_asset": f"{hostname} (expired {abs(days_left)} days ago)",
                })
            elif days_left <= 7:
                findings.append({
                    "severity": "critical",
                    "category": "ssl_expiring_soon",
                    "title": f"SSL Certificate Expires in {days_left} Days",
                    "description": f"Your SSL certificate expires very soon ({days_left} days). After it expires, all visitors will see a security warning.",
                    "fix_steps": "1. Renew your SSL certificate now — don't wait\n2. If using Let's Encrypt: certbot renew\n3. Set up auto-renewal to avoid this in future",
                    "affected_asset": f"{hostname} (expires {not_after})",
                })
            elif days_left <= 30:
                findings.append({
                    "severity": "medium",
                    "category": "ssl",
                    "title": f"SSL Certificate Expires in {days_left} Days",
                    "description": f"Your SSL certificate will expire in {days_left} days. Plan renewal soon.",
                    "fix_steps": "1. Schedule SSL certificate renewal\n2. Consider automating with Let's Encrypt certbot",
                    "affected_asset": f"{hostname} (expires {not_after})",
                })
        except Exception:
            pass

    # TLS version check
    if tls_version in ("TLSv1", "TLSv1.1"):
        findings.append({
            "severity": "critical",
            "category": "ssl",
            "title": f"Outdated TLS Version: {tls_version}",
            "description": f"Your site supports {tls_version}, which has known security vulnerabilities. Modern browsers and payment processors reject these old versions.",
            "fix_steps": f"1. Disable {tls_version} in your web server configuration\n2. Only allow TLS 1.2 and TLS 1.3\n3. For Apache: SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1\n4. For Nginx: ssl_protocols TLSv1.2 TLSv1.3;",
            "affected_asset": f"{hostname} ({tls_version})",
        })

    return findings


def _check_sslyze(hostname: str, port: int) -> list[dict]:
    """Optional deeper SSL check via sslyze."""
    findings = []
    try:
        from sslyze import Scanner, ServerNetworkLocation, ServerScanRequest
        from sslyze.plugins.scan_commands import ScanCommand

        server = ServerNetworkLocation(hostname, port)
        scanner = Scanner()
        scanner.queue_scans([ServerScanRequest(server_location=server, scan_commands={
            ScanCommand.CERTIFICATE_INFO,
            ScanCommand.SSL_2_0_CIPHER_SUITES,
            ScanCommand.SSL_3_0_CIPHER_SUITES,
        })])
        for result in scanner.get_results():
            if result.scan_result:
                # Check for SSL 2.0 / 3.0 support
                for suite_result in [result.scan_result.ssl_2_0_cipher_suites,
                                     result.scan_result.ssl_3_0_cipher_suites]:
                    if suite_result and suite_result.accepted_cipher_suites:
                        findings.append({
                            "severity": "critical",
                            "category": "ssl",
                            "title": "Server Supports Deprecated SSL Protocol",
                            "description": "Your server supports SSL 2.0 or 3.0, which are completely broken protocols from the 1990s. Any data encrypted with them can be decrypted by attackers.",
                            "fix_steps": "1. Disable SSL 2.0 and SSL 3.0 on your server immediately\n2. Only enable TLS 1.2 and TLS 1.3",
                            "affected_asset": hostname,
                        })
    except Exception:
        pass
    return findings
