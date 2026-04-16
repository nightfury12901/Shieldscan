"""
Exposed config & secret file scanner.
Flags known sensitive filenames: .env, private keys, db dumps, etc.
"""
import re
from pathlib import PurePosixPath

# ─────────────────────────────────────────────
# Dangerous filenames
# ─────────────────────────────────────────────
DANGEROUS_FILE_PATTERNS = [
    # .env files
    (re.compile(r"(^|/)\.env(\.[a-z]+)?$", re.IGNORECASE), "critical", "exposed_env",
     "A .env file was found committed to the repository. .env files typically contain database passwords, API keys, and other secrets — committing them exposes all your secrets to anyone who can read the code.",
     "1. Remove the .env file from git: git rm --cached .env\n2. Add .env to your .gitignore file NOW\n3. Rotate all secrets that were in the .env file immediately — they are compromised\n4. Use environment variables from your hosting platform instead"),

    # Private keys
    (re.compile(r"(^|/)(id_rsa|id_dsa|id_ecdsa|id_ed25519)(\.pub)?$"), "critical", "private_key_committed",
     "A private SSH key file was committed to the repository. With this key, anyone can log into any server it's authorized on.",
     "1. Delete this file from the repository history immediately (use git filter-branch or BFG Repo Cleaner)\n2. Generate a new SSH key pair\n3. Revoke the old key from all servers\n4. Add private key files to .gitignore"),

    # PEM files
    (re.compile(r"(^|/).*\.(pem|key|p12|pfx|crt)$", re.IGNORECASE), "critical", "private_key_committed",
     "A cryptographic key or certificate file was found in the repository. Private keys committed to repos are frequently harvested by automated scanners.",
     "1. Remove the key file from repository history\n2. Regenerate the key/certificate\n3. Revoke the old certificate\n4. Add *.pem, *.key to .gitignore"),

    # WordPress config
    (re.compile(r"(^|/)wp-config\.php$"), "critical", "exposed_config",
     "wp-config.php was found in the repository. This file contains your WordPress database credentials in plain text.",
     "1. Remove wp-config.php from the repository\n2. Rotate your WordPress database password\n3. Add wp-config.php to .gitignore"),

    # Credentials files
    (re.compile(r"(^|/)(credentials|secrets|service.?account)\.json$", re.IGNORECASE), "critical", "exposed_config",
     "A credentials or secrets JSON file was committed to the repository.",
     "1. Remove this file from the repository\n2. Rotate all credentials stored in this file\n3. Use a secrets manager instead"),

    # Database dumps
    (re.compile(r"(^|/).*\.(sql|sqlite|db|sqlite3)$", re.IGNORECASE), "medium", "database_dump",
     "A database file or dump was found in the repository. This could contain all your customer data, passwords, and business records.",
     "1. Remove the database file from the repository\n2. Check if it contains sensitive customer data\n3. If it was ever pushed to a public repo, notify affected users\n4. Add *.sql, *.db, *.sqlite to .gitignore"),

    # Backup files
    (re.compile(r"(^|/).*\.(bak|old|backup|orig)$", re.IGNORECASE), "low", "backup_file",
     "A backup file was found in the repository. Backup files often contain old versions of sensitive configuration.",
     "1. Remove backup files from the repository\n2. Review the content for any sensitive data\n3. Add *.bak, *.old to .gitignore"),

    # Docker compose with secrets
    (re.compile(r"(^|/)docker-compose(\.override|\.prod|\.staging)?\.yml$", re.IGNORECASE), None, None, None, None),

    # htpasswd
    (re.compile(r"(^|/)\.htpasswd$"), "critical", "exposed_credentials",
     "An .htpasswd file containing hashed credentials was found in the repository.",
     "1. Remove .htpasswd from the repository\n2. Regenerate your access credentials\n3. Add .htpasswd to .gitignore"),

    # Kubernetes secrets
    (re.compile(r"(^|/).*(secret|credential).*\.ya?ml$", re.IGNORECASE), "critical", "k8s_secret",
     "A Kubernetes secret YAML file may be committed. These files often contain base64-encoded credentials.",
     "1. Remove this file from the repository\n2. Rotate any credentials it contains\n3. Use Kubernetes Secrets properly — store them in a secrets manager, not in git"),
]

DOCKER_COMPOSE_PASSWORD = re.compile(r"(?i)(MYSQL_ROOT_PASSWORD|POSTGRES_PASSWORD|MARIADB_ROOT_PASSWORD)\s*:\s*[^\n]+")


def _has_real_content(content: str) -> bool:
    """Return True only if the file has at least one non-empty, non-comment line."""
    for line in content.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            return True
    return False


# Filename suffixes that are always safe to ignore even if they match a pattern
SAFE_SUFFIXES = {".example", ".sample", ".template", ".dist"}


async def scan_config_files(files: list[dict]) -> list[dict]:
    findings = []
    seen_paths = set()

    for file_obj in files:
        path = file_obj.get("path", "")
        content = file_obj.get("content", "")

        # Skip node_modules / dist
        if any(skip in path for skip in ["node_modules/", "vendor/", ".git/", "dist/"]):
            continue

        # Skip template / example env files (e.g. .env.example, .env.sample)
        lower_path = path.lower()
        if any(lower_path.endswith(suffix) for suffix in SAFE_SUFFIXES):
            continue
        # Also skip if the filename itself contains 'example' or 'sample'
        basename = lower_path.split("/")[-1]
        if any(kw in basename for kw in ("example", "sample", "template", ".dist")):
            continue

        for pattern_tuple in DANGEROUS_FILE_PATTERNS:
            if len(pattern_tuple) == 5:
                file_pattern, severity, category, description, fix_steps = pattern_tuple
            else:
                continue

            if file_pattern.search(path):
                if path in seen_paths:
                    continue
                seen_paths.add(path)

                if severity is None:
                    # Docker compose — check for hardcoded passwords
                    matches = DOCKER_COMPOSE_PASSWORD.findall(content)
                    if matches:
                        findings.append({
                            "severity": "critical",
                            "category": "exposed_config",
                            "title": f"Hardcoded Database Password in Docker Compose",
                            "description": "A database password is hardcoded in your docker-compose file. Anyone with repo access can read your production database password.",
                            "fix_steps": "1. Remove hardcoded passwords from docker-compose.yml\n2. Use environment variables: ${MYSQL_ROOT_PASSWORD}\n3. Store secrets in a .env file (not committed) or a secrets manager",
                            "affected_asset": path,
                        })
                elif category == "exposed_env":
                    # Only flag .env files that actually contain real key-value pairs
                    # (non-empty, non-comment lines). An empty or comment-only .env
                    # is a false positive.
                    if _has_real_content(content):
                        findings.append({
                            "severity": severity,
                            "category": category,
                            "title": f"Sensitive File Exposed in Repository: {path.split('/')[-1]}",
                            "description": description,
                            "fix_steps": fix_steps,
                            "affected_asset": path,
                        })
                else:
                    findings.append({
                        "severity": severity,
                        "category": category,
                        "title": f"Sensitive File Exposed in Repository: {path.split('/')[-1]}",
                        "description": description,
                        "fix_steps": fix_steps,
                        "affected_asset": path,
                    })
                break

    return findings
