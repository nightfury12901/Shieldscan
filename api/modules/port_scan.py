"""
Port scanner using asyncio.open_connection() — no nmap binary required.
Scans exactly the 13 specified critical ports concurrently.
3-second timeout per port.
"""
import asyncio
from urllib.parse import urlparse

# Exact port list from spec
CRITICAL_PORTS = {
    21:    ("FTP",           "critical", "FTP (File Transfer Protocol) exposes your server to unauthenticated file access. An attacker can potentially read, upload, or delete files on your server."),
    22:    ("SSH",           "medium",   "SSH (remote server access) is exposed to the internet. Attackers can attempt to brute-force your server password to gain full control of your server."),
    23:    ("Telnet",        "critical", "Telnet transmits all data — including passwords — in plain text. Any attacker who can intercept traffic will see your credentials immediately."),
    25:    ("SMTP",          "medium",   "Your mail server is publicly accessible. If misconfigured, it can be used by spammers to send emails pretending to be from your business."),
    3306:  ("MySQL",         "critical", "Your MySQL database server is exposed to the internet. An attacker can attempt to log into your database directly, risking all your customer data."),
    5432:  ("PostgreSQL",    "critical", "Your PostgreSQL database is exposed to the internet. This gives attackers a direct path to attack your database and steal or destroy data."),
    5984:  ("CouchDB",       "critical", "CouchDB is accessible from the internet. If default credentials haven't been changed, attackers can read and delete all your data."),
    6379:  ("Redis",         "critical", "Redis is exposed to the internet and typically has no authentication by default. An attacker can read all cached data, including sessions and tokens."),
    8080:  ("HTTP-Alt",      "low",      "An alternate HTTP port is open, potentially running a development server or admin panel that should not be publicly accessible."),
    8443:  ("HTTPS-Alt",     "low",      "An alternate HTTPS port is open. Verify this is intentional — it may be an admin interface that should be restricted."),
    9200:  ("Elasticsearch", "critical", "Elasticsearch is publicly accessible and has no authentication by default. Attackers can query, download, or delete all your stored data."),
    11211: ("Memcached",     "critical", "Memcached is exposed to the internet with no authentication. Attackers can read all cached data including sessions, and abuse it for DDoS amplification attacks."),
    27017: ("MongoDB",       "critical", "MongoDB is exposed to the internet. Many MongoDB databases have no password by default — your entire database could be readable by anyone."),
}

FIX_STEPS = {
    21:    "1. Disable FTP and use SFTP instead (port 22)\n2. If FTP is required, restrict access to specific IP addresses using your firewall\n3. Never allow anonymous FTP access",
    22:    "1. Use key-based authentication instead of passwords\n2. Restrict SSH access to specific trusted IP addresses via firewall\n3. Change SSH to a non-standard port (security through obscurity, not a replacement for the above)\n4. Use fail2ban to block repeated login attempts",
    23:    "1. Disable Telnet immediately — it is completely insecure\n2. Use SSH instead (port 22)\n3. Block port 23 in your firewall",
    25:    "1. Restrict SMTP to only accept connections from your mail server\n2. Implement SPF, DKIM, and DMARC to prevent email spoofing\n3. If you don't run your own mail server, block port 25",
    3306:  "1. Bind MySQL to 127.0.0.1 (localhost only) in /etc/mysql/mysql.conf.d/mysqld.cnf: bind-address = 127.0.0.1\n2. Block port 3306 in your firewall\n3. Use a database proxy or VPN for remote access",
    5432:  "1. Bind PostgreSQL to localhost: in postgresql.conf, set listen_addresses = 'localhost'\n2. Block port 5432 in your firewall",
    5984:  "1. Block port 5984 in your firewall\n2. Enable CouchDB authentication\n3. Bind CouchDB to localhost if only used internally",
    6379:  "1. Add a strong password to Redis: requirepass yourpassword in redis.conf\n2. Bind Redis to localhost: bind 127.0.0.1\n3. Block port 6379 in your firewall",
    8080:  "1. Investigate what is running on port 8080\n2. If it's a dev server, shut it down on production\n3. If it's needed, restrict access to specific IPs",
    8443:  "1. Investigate what is running on port 8443\n2. Restrict access via firewall if this is an admin interface",
    9200:  "1. Block port 9200 in your firewall immediately\n2. Enable Elasticsearch security: xpack.security.enabled: true\n3. Bind to localhost: network.host: localhost",
    11211: "1. Block port 11211 in your firewall immediately\n2. Bind Memcached to localhost: -l 127.0.0.1 in /etc/memcached.conf",
    27017: "1. Enable MongoDB authentication\n2. Bind to localhost: net.bindIp: 127.0.0.1 in mongod.conf\n3. Block port 27017 in your firewall",
}


async def scan_ports(url: str) -> list[dict]:
    parsed = urlparse(url)
    hostname = parsed.hostname

    if not hostname:
        return [{
            "severity": "low",
            "category": "ports",
            "title": "Could not determine hostname for port scan",
            "description": "The URL did not contain a valid hostname.",
            "fix_steps": "Provide a full URL including the domain name.",
            "affected_asset": url,
        }]

    # Run all port checks concurrently
    tasks = [_check_port(hostname, port) for port in CRITICAL_PORTS]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    findings = []
    for result in results:
        if isinstance(result, dict) and result.get("open"):
            port = result["port"]
            name, severity, description = CRITICAL_PORTS[port]
            # Downgrade SSH to low if it's the only finding (SSH being open isn't always bad)
            if port == 22:
                severity = "low"
            findings.append({
                "severity": severity,
                "category": "dangerous_open_port",
                "title": f"Dangerous Port Open: {port}/{name}",
                "description": description,
                "fix_steps": FIX_STEPS.get(port, "Block this port in your server firewall."),
                "affected_asset": f"{hostname}:{port} ({name})",
            })

    return findings


async def _check_port(hostname: str, port: int) -> dict:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(hostname, port),
            timeout=3.0
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return {"port": port, "open": True}
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return {"port": port, "open": False}
    except Exception:
        return {"port": port, "open": False}
