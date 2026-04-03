"""
Dependency vulnerability scanner.
Parses package manifests and cross-references with NVD CVE API.
"""
import re
import json
import asyncio
from typing import Any
from modules.cve_lookup import lookup_cves_for_packages


def _get_parsers() -> dict:
    return {
        "package.json":     _parse_npm,
        "requirements.txt": _parse_pip,
        "Pipfile":          _parse_pipfile,
        "Gemfile":          _parse_gemfile,
        "go.mod":           _parse_gomod,
        "composer.json":    _parse_composer,
        "pom.xml":          _parse_maven,
        "build.gradle":     _parse_gradle,
    }


async def scan_dependencies(files: list[dict]) -> list[dict]:
    """Parse dependency files and look up CVEs for all packages."""
    parsers = _get_parsers()
    all_packages = []
    for file_obj in files:
        fname = file_obj.get("path", "").split("/")[-1]
        content = file_obj.get("content", "")
        parser = parsers.get(fname)
        if parser:
            try:
                packages = parser(content)
                all_packages.extend(packages)
            except Exception:
                pass

    if not all_packages:
        return []

    seen = set()
    unique = []
    for p in all_packages:
        key = f"{p['name']}@{p.get('version','')}"
        if key not in seen:
            seen.add(key)
            unique.append(p)

    return await lookup_cves_for_packages(unique[:50])


# ─────────────────────────────────────────────
# Parsers
# ─────────────────────────────────────────────

def _parse_npm(content: str) -> list[dict]:
    packages = []
    try:
        data = json.loads(content)
        for section in ("dependencies", "devDependencies"):
            for name, version in data.get(section, {}).items():
                version = re.sub(r"[\^~>=<]", "", version).strip()
                packages.append({"name": name, "version": version, "ecosystem": "npm"})
    except Exception:
        pass
    return packages


def _parse_pip(content: str) -> list[dict]:
    packages = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Match: package==version, package>=version, package
        m = re.match(r"^([A-Za-z0-9_\-\.]+)\s*(?:[><=!]+\s*([0-9][^\s;,]*))?", line)
        if m:
            packages.append({"name": m.group(1), "version": m.group(2) or "", "ecosystem": "pypi"})
    return packages


def _parse_pipfile(content: str) -> list[dict]:
    packages = []
    in_packages = False
    for line in content.splitlines():
        if line.strip() in ("[packages]", "[dev-packages]"):
            in_packages = True
            continue
        if line.startswith("["):
            in_packages = False
        if in_packages and "=" in line:
            parts = line.split("=", 1)
            name = parts[0].strip().strip('"')
            version = parts[1].strip().strip('"').strip()
            packages.append({"name": name, "version": version, "ecosystem": "pypi"})
    return packages


def _parse_gemfile(content: str) -> list[dict]:
    packages = []
    for m in re.finditer(r"gem\s+['\"]([^'\"]+)['\"](?:\s*,\s*['\"]([^'\"]+)['\"])?", content):
        packages.append({"name": m.group(1), "version": m.group(2) or "", "ecosystem": "rubygems"})
    return packages


def _parse_gomod(content: str) -> list[dict]:
    packages = []
    for m in re.finditer(r"^\s+([^\s]+)\s+v([^\s]+)", content, re.MULTILINE):
        packages.append({"name": m.group(1), "version": m.group(2), "ecosystem": "go"})
    return packages


def _parse_composer(content: str) -> list[dict]:
    packages = []
    try:
        data = json.loads(content)
        for section in ("require", "require-dev"):
            for name, version in data.get(section, {}).items():
                if name == "php":
                    continue
                version = re.sub(r"[\^~>=<]", "", version).strip()
                packages.append({"name": name, "version": version, "ecosystem": "packagist"})
    except Exception:
        pass
    return packages


def _parse_maven(content: str) -> list[dict]:
    packages = []
    deps = re.findall(
        r"<dependency>.*?<groupId>([^<]+)</groupId>.*?<artifactId>([^<]+)</artifactId>.*?(?:<version>([^<]+)</version>)?.*?</dependency>",
        content, re.DOTALL
    )
    for group, artifact, version in deps:
        packages.append({"name": f"{group.strip()}:{artifact.strip()}", "version": version.strip() if version else "", "ecosystem": "maven"})
    return packages


def _parse_gradle(content: str) -> list[dict]:
    packages = []
    for m in re.finditer(r"(?:implementation|compile|api|testImplementation)\s+['\"]([^'\"]+)['\"]", content):
        parts = m.group(1).split(":")
        if len(parts) >= 2:
            packages.append({"name": parts[1], "version": parts[2] if len(parts) > 2 else "", "ecosystem": "maven"})
    return packages
