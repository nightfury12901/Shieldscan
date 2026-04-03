import os
import io
import asyncio
import uuid
import ipaddress
import re
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, validator
from dotenv import load_dotenv

load_dotenv()

from modules.db import get_supabase
from modules.headers import scan_headers
from modules.ssl_scan import scan_ssl
from modules.dns_scan import scan_dns
from modules.cms_scan import scan_cms
from modules.port_scan import scan_ports
from modules.breach_check import check_breach
from modules.blacklist_check import check_blacklist
from modules.cve_lookup import lookup_cves
from modules.zap_scan import scan_zap
from modules.secret_scan import scan_secrets
from modules.dependency_scan import scan_dependencies
from modules.code_pattern_scan import scan_code_patterns
from modules.config_file_scan import scan_config_files
from modules.auth_scan import scan_auth_issues
from modules.risk_score import compute_risk_score
from modules.ai_report import generate_ai_report
from modules.pdf_report import generate_pdf
from modules.webhook import send_slack_webhook
from modules.github_pr import generate_github_autofix_pr

# ─────────────────────────────────────────────
# App setup
# ─────────────────────────────────────────────
app = FastAPI(title="ShieldScan API", version="1.0.0")

FRONTEND_URL = os.getenv("FRONTEND_URL", "*")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_URL] if FRONTEND_URL != "*" else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────────
# Input validation helpers
# ─────────────────────────────────────────────
PRIVATE_IP_PATTERNS = [
    re.compile(r"^10\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),
    re.compile(r"^127\."),
    re.compile(r"^localhost$", re.IGNORECASE),
    re.compile(r"^::1$"),
]

def is_private_target(url: str) -> bool:
    import urllib.parse
    try:
        hostname = urllib.parse.urlparse(url).hostname or ""
        for pat in PRIVATE_IP_PATTERNS:
            if pat.match(hostname):
                return True
        try:
            addr = ipaddress.ip_address(hostname)
            return addr.is_private or addr.is_loopback
        except ValueError:
            pass
    except Exception:
        pass
    return False

def validate_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        raise HTTPException(400, "URL must start with http:// or https://")
    if is_private_target(url):
        raise HTTPException(400, "Private/loopback IP addresses are not allowed (SSRF protection)")
    return url

GITHUB_RE = re.compile(r"^https://github\.com/[\w\-\.]+/[\w\-\.]+", re.IGNORECASE)

def validate_github_url(url: str) -> str:
    if not GITHUB_RE.match(url):
        raise HTTPException(400, "URL must match https://github.com/owner/repo")
    return url

# ─────────────────────────────────────────────
# Progress updater (Supabase Realtime via row update)
# ─────────────────────────────────────────────
async def update_progress(scan_id: str, progress: int, status: str = "running"):
    try:
        supabase = get_supabase()
        update_data = {"progress": progress, "status": status}
        if status == "done":
            update_data["completed_at"] = datetime.utcnow().isoformat()
        supabase.table("scans").update(update_data).eq("id", scan_id).execute()
    except Exception:
        pass  # Never crash on progress update

# ─────────────────────────────────────────────
# Module runner with timeout + graceful fallback
# ─────────────────────────────────────────────
async def run_module(name: str, coro, timeout: int = 15) -> dict:
    try:
        result = await asyncio.wait_for(coro, timeout=timeout)
        return {"module": name, "status": "ok", "findings": result}
    except asyncio.TimeoutError:
        return {"module": name, "status": "timeout", "findings": []}
    except Exception as e:
        return {"module": name, "status": "error", "error": str(e), "findings": []}

# ─────────────────────────────────────────────
# INSERT findings to DB
# ─────────────────────────────────────────────
def insert_findings(scan_id: str, findings: list[dict]):
    if not findings:
        return
    supabase = get_supabase()
    rows = []
    for f in findings:
        rows.append({
            "scan_id": scan_id,
            "severity": f.get("severity", "low"),
            "category": f.get("category", "misc"),
            "title": f.get("title", ""),
            "description": f.get("description", ""),
            "fix_steps": f.get("fix_steps", ""),
            "affected_asset": f.get("affected_asset", ""),
            "line_number": f.get("line_number"),
        })
    supabase.table("findings").insert(rows).execute()

# ─────────────────────────────────────────────
# Pydantic request models
# ─────────────────────────────────────────────
class UrlScanRequest(BaseModel):
    url: str
    user_id: Optional[str] = None
    webhook_url: Optional[str] = None

class GithubScanRequest(BaseModel):
    repo_url: str
    github_pat: Optional[str] = None
    user_id: Optional[str] = None
    webhook_url: Optional[str] = None

class ZipScanRequest(BaseModel):
    storage_path: str
    user_id: Optional[str] = None
    webhook_url: Optional[str] = None

class AutoFixRequest(BaseModel):
    scan_id: str
    finding_id: str
    github_pat: str

# ─────────────────────────────────────────────
# HEALTH CHECK
# ─────────────────────────────────────────────
@app.get("/api/health")
async def health():
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}

# ─────────────────────────────────────────────
# POST /api/scan/url
# ─────────────────────────────────────────────
@app.post("/api/scan/url")
async def scan_url(req: UrlScanRequest, background_tasks: BackgroundTasks):
    url = validate_url(req.url)
    supabase = get_supabase()

    scan_row = supabase.table("scans").insert({
        "user_id": req.user_id,
        "scan_type": "url",
        "target": url,
        "status": "running",
        "progress": 0,
    }).execute()
    scan_id = scan_row.data[0]["id"]

    background_tasks.add_task(_run_url_scan, scan_id, url, req.webhook_url)
    return {"scan_id": scan_id, "status": "running"}

async def _run_webhook_wrapper(webhook_url: str, target: str, risk_score: int, findings: list, scan_id: str):
    if not webhook_url:
        return
    c = sum(1 for f in findings if f.get("severity") == "critical")
    m = sum(1 for f in findings if f.get("severity") == "medium")
    l = sum(1 for f in findings if f.get("severity") == "low")
    frontend = FRONTEND_URL if FRONTEND_URL != "*" else "http://localhost:5173"
    await send_slack_webhook(webhook_url, target, risk_score, c, m, l, f"{frontend}/results/{scan_id}")

async def _run_url_scan(scan_id: str, url: str, webhook_url: str = None):
    supabase = get_supabase()
    try:
        # Run all 9 modules in parallel
        results = await asyncio.gather(
            run_module("headers",   scan_headers(url)),
            run_module("ssl",       scan_ssl(url)),
            run_module("dns",       scan_dns(url)),
            run_module("cms",       scan_cms(url)),
            run_module("ports",     scan_ports(url)),
            run_module("breach",    check_breach(url)),
            run_module("blacklist", check_blacklist(url)),
            run_module("cve",       lookup_cves(url)),
            run_module("zap",       scan_zap(url)),
        )

        # Aggregate findings
        module_statuses = {}
        all_findings = []
        for r in results:
            module_statuses[r["module"]] = r["status"]
            all_findings.extend(r.get("findings", []))

        # Update progress: modules done
        await update_progress(scan_id, 80)

        # Risk score
        risk_score = compute_risk_score(all_findings)

        # AI report
        ai_report = await generate_ai_report(all_findings)

        # Update progress: AI done
        await update_progress(scan_id, 95)

        # Store findings
        insert_findings(scan_id, all_findings)

        # Finalize scan row
        supabase.table("scans").update({
            "status": "done",
            "progress": 100,
            "risk_score": risk_score,
            "raw_json": {"modules": results, "module_statuses": module_statuses},
            "ai_report": ai_report,
            "completed_at": datetime.utcnow().isoformat(),
        }).eq("id", scan_id).execute()

        await _run_webhook_wrapper(webhook_url, url, risk_score, all_findings, scan_id)

    except Exception as e:
        supabase.table("scans").update({
            "status": "failed",
            "raw_json": {"error": str(e)},
        }).eq("id", scan_id).execute()

# ─────────────────────────────────────────────
# POST /api/autofix
# ─────────────────────────────────────────────
import httpx

@app.post("/api/autofix")
async def autofix(req: AutoFixRequest):
    supabase = get_supabase()
    
    # 1. Get finding & scan
    finding_res = supabase.table("findings").select("*").eq("id", req.finding_id).execute()
    if not finding_res.data:
        raise HTTPException(404, "Finding not found")
    finding = finding_res.data[0]

    scan_res = supabase.table("scans").select("*").eq("id", req.scan_id).execute()
    if not scan_res.data:
        raise HTTPException(404, "Scan not found")
    scan = scan_res.data[0]

    if scan["scan_type"] != "github":
        raise HTTPException(400, "Auto-fix is currently only supported for GitHub scans.")
    
    file_path = finding.get("affected_asset")
    if not file_path or not isinstance(file_path, str) or ":" in file_path:
        raise HTTPException(400, "Finding does not have a clearly patchable file path.")

    # 2. Fetch file content from GitHub
    repo_url = scan["target"]
    from urllib.parse import urlparse
    path_parts = urlparse(repo_url).path.strip("/").split("/")
    owner, repo = path_parts[0], path_parts[1]

    from modules.ai_report import GROQ_API_URL
    groq_api_key = os.getenv("GROQ_API_KEY")
    if not groq_api_key:
        raise HTTPException(500, "Groq API key not configured")

    gh_headers = {
        "Authorization": f"Bearer {req.github_pat}",
        "Accept": "application/vnd.github.v3.raw"
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        # Fetch raw file content directly (v3.raw returns the file bytes, not JSON)
        resp = await client.get(
            f"https://api.github.com/repos/{owner}/{repo}/contents/{file_path}",
            headers=gh_headers
        )
        if resp.status_code != 200:
            raise HTTPException(400, f"Cannot fetch file from GitHub: {resp.text}")

        original_content = resp.text

        # 3. AI Rewrite
        prompt = f"You are an expert security engineer fixing a vulnerability in the file '{file_path}'.\n\n"
        prompt += f"VULNERABILITY: {finding['title']}\n{finding['description']}\n\n"
        prompt += f"DIRECTIONS: {finding['fix_steps']}\n\n"
        prompt += "ORIGINAL CODE:\n```\n" + original_content + "\n```\n\n"
        prompt += "REWRITE THE ENTIRE FILE. You must return ONLY the complete, fully patched source code for the file. Do NOT return just a snippet. Do not use markdown backticks around the final response, return RAW text."

        ai_resp = await client.post(
            GROQ_API_URL,
            headers={"Authorization": f"Bearer {groq_api_key}", "Content-Type": "application/json"},
            json={
                "model": "llama3-70b-8192",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1
            },
        )
        if ai_resp.status_code != 200:
            raise HTTPException(500, f"AI fix generation failed: {ai_resp.text}")

        new_content = ai_resp.json()["choices"][0]["message"]["content"].strip()
        if new_content.startswith("```"):
            new_content = new_content.split("\n", 1)[1].rsplit("\n", 1)[0]

    # 4. Open PR
    try:
        pr_url = await generate_github_autofix_pr(
            repo_url=repo_url,
            pat=req.github_pat,
            file_path=file_path,
            new_content=new_content,
            title=finding['title'],
            description=finding['description']
        )
        return {"status": "ok", "pr_url": pr_url}
    except Exception as e:
        raise HTTPException(500, str(e))

# ─────────────────────────────────────────────
# POST /api/scan/github
# ─────────────────────────────────────────────
@app.post("/api/scan/github")
async def scan_github(req: GithubScanRequest, background_tasks: BackgroundTasks):
    repo_url = validate_github_url(req.repo_url)
    supabase = get_supabase()

    scan_row = supabase.table("scans").insert({
        "user_id": req.user_id,
        "scan_type": "github",
        "target": repo_url,
        "status": "running",
        "progress": 0,
    }).execute()
    scan_id = scan_row.data[0]["id"]

    background_tasks.add_task(_run_github_scan, scan_id, repo_url, req.github_pat, req.webhook_url)
    return {"scan_id": scan_id, "status": "running"}

async def _run_github_scan(scan_id: str, repo_url: str, pat: Optional[str], webhook_url: Optional[str] = None):
    supabase = get_supabase()
    try:
        # Fetch file tree from GitHub REST API
        files = await _fetch_github_files(repo_url, pat)
        await update_progress(scan_id, 20)

        # Run code analysis modules in parallel
        results = await asyncio.gather(
            run_module("secrets",      scan_secrets(files)),
            run_module("dependencies", scan_dependencies(files)),
            run_module("code_patterns",scan_code_patterns(files)),
            run_module("config_files", scan_config_files(files)),
            run_module("auth_issues",  scan_auth_issues(files)),
        )

        await update_progress(scan_id, 80)

        all_findings = []
        module_statuses = {}
        for r in results:
            module_statuses[r["module"]] = r["status"]
            all_findings.extend(r.get("findings", []))

        risk_score = compute_risk_score(all_findings)
        ai_report = await generate_ai_report(all_findings)

        await update_progress(scan_id, 95)
        insert_findings(scan_id, all_findings)

        supabase.table("scans").update({
            "status": "done",
            "progress": 100,
            "risk_score": risk_score,
            "raw_json": {"modules": results, "module_statuses": module_statuses},
            "ai_report": ai_report,
            "completed_at": datetime.utcnow().isoformat(),
        }).eq("id", scan_id).execute()

        await _run_webhook_wrapper(webhook_url, repo_url, risk_score, all_findings, scan_id)

    except Exception as e:
        supabase.table("scans").update({
            "status": "failed",
            "raw_json": {"error": str(e)},
        }).eq("id", scan_id).execute()

async def _fetch_github_files(repo_url: str, pat: Optional[str]) -> list[dict]:
    """Fetch file tree + contents from GitHub REST API."""
    import httpx
    # Parse owner/repo from URL
    parts = repo_url.rstrip("/").split("/")
    owner, repo = parts[-2], parts[-1]
    if repo.endswith(".git"):
        repo = repo[:-4]

    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if pat:
        headers["Authorization"] = f"Bearer {pat}"
    elif os.getenv("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {os.getenv('GITHUB_TOKEN')}"

    files = []
    async with httpx.AsyncClient(timeout=15) as client:
        # Get default branch
        repo_resp = await client.get(f"https://api.github.com/repos/{owner}/{repo}", headers=headers)
        if repo_resp.status_code != 200:
            raise HTTPException(400, f"GitHub repo not found or not accessible: {repo_resp.status_code}")
        default_branch = repo_resp.json().get("default_branch", "main")

        # Get full file tree (recursive)
        tree_resp = await client.get(
            f"https://api.github.com/repos/{owner}/{repo}/git/trees/{default_branch}?recursive=1",
            headers=headers
        )
        if tree_resp.status_code != 200:
            raise HTTPException(400, "Could not fetch repository tree")

        tree = tree_resp.json().get("tree", [])
        # Filter to interesting files, limit to 200
        interesting = [
            f for f in tree
            if f["type"] == "blob" and f.get("size", 0) < 500_000
            and not any(skip in f["path"] for skip in [".min.js", "node_modules", ".git", "vendor/"])
        ][:200]

        # Fetch file contents in batches of 20
        for i in range(0, len(interesting), 20):
            batch = interesting[i:i+20]
            tasks = []
            for file_info in batch:
                tasks.append(
                    client.get(
                        f"https://api.github.com/repos/{owner}/{repo}/contents/{file_info['path']}?ref={default_branch}",
                        headers=headers
                    )
                )
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            for file_info, resp in zip(batch, responses):
                if isinstance(resp, Exception):
                    continue
                if resp.status_code == 200:
                    data = resp.json()
                    content_b64 = data.get("content", "")
                    if content_b64:
                        import base64
                        try:
                            content = base64.b64decode(content_b64).decode("utf-8", errors="ignore")
                            files.append({"path": file_info["path"], "content": content})
                        except Exception:
                            pass
    return files

# ─────────────────────────────────────────────
# POST /api/scan/zip
# ─────────────────────────────────────────────
@app.post("/api/scan/zip")
async def scan_zip(req: ZipScanRequest, background_tasks: BackgroundTasks):
    supabase = get_supabase()
    scan_row = supabase.table("scans").insert({
        "user_id": req.user_id,
        "scan_type": "zip",
        "target": req.storage_path,
        "status": "running",
        "progress": 0,
    }).execute()
    scan_id = scan_row.data[0]["id"]

    background_tasks.add_task(_run_zip_scan, scan_id, req.storage_path)
    return {"scan_id": scan_id, "status": "running"}

async def _run_zip_scan(scan_id: str, storage_path: str):
    import zipfile, tempfile, shutil, pathlib
    supabase = get_supabase()
    tmp_dir = None
    try:
        # Download ZIP from Supabase Storage
        signed = supabase.storage.from_("zip-uploads").create_signed_url(
            storage_path.replace("zip-uploads/", ""), 300
        )
        signed_url = signed.get("signedURL") or signed.get("signedUrl")
        if not signed_url:
            raise ValueError("Could not get signed URL for ZIP")

        import httpx
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(signed_url)
            zip_bytes = resp.content

        # Validate ZIP magic bytes
        if not zip_bytes[:4] == b"PK\x03\x04":
            raise ValueError("Invalid ZIP file (bad magic bytes)")

        # Extract to temp dir with path traversal protection
        tmp_dir = tempfile.mkdtemp(prefix="shieldscan_")
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            for member in zf.namelist():
                # Path traversal protection
                if ".." in member or member.startswith("/") or member.startswith("\\"):
                    continue
                member_path = pathlib.Path(tmp_dir) / member
                if not str(member_path).startswith(tmp_dir):
                    continue
                zf.extract(member, tmp_dir)

        await update_progress(scan_id, 20)

        # Build file list
        files = []
        for root, _, filenames in os.walk(tmp_dir):
            for fname in filenames:
                fpath = os.path.join(root, fname)
                rel_path = os.path.relpath(fpath, tmp_dir)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    files.append({"path": rel_path, "content": content})
                except Exception:
                    pass

        # Run all code analysis modules in parallel
        results = await asyncio.gather(
            run_module("secrets",       scan_secrets(files)),
            run_module("dependencies",  scan_dependencies(files)),
            run_module("code_patterns", scan_code_patterns(files)),
            run_module("config_files",  scan_config_files(files)),
            run_module("auth_issues",   scan_auth_issues(files)),
        )

        await update_progress(scan_id, 80)

        all_findings = []
        module_statuses = {}
        for r in results:
            module_statuses[r["module"]] = r["status"]
            all_findings.extend(r.get("findings", []))

        risk_score = compute_risk_score(all_findings)
        ai_report = await generate_ai_report(all_findings)
        await update_progress(scan_id, 95)
        insert_findings(scan_id, all_findings)

        supabase.table("scans").update({
            "status": "done",
            "progress": 100,
            "risk_score": risk_score,
            "raw_json": {"modules": results, "module_statuses": module_statuses},
            "ai_report": ai_report,
            "completed_at": datetime.utcnow().isoformat(),
        }).eq("id", scan_id).execute()

    except Exception as e:
        supabase.table("scans").update({
            "status": "failed",
            "raw_json": {"error": str(e)},
        }).eq("id", scan_id).execute()
    finally:
        # Cleanup temp dir
        if tmp_dir and os.path.exists(tmp_dir):
            try:
                import shutil
                shutil.rmtree(tmp_dir)
            except Exception:
                pass
        # Optionally delete from Supabase Storage (scheduled elsewhere)

# ─────────────────────────────────────────────
# GET /api/history/{target}
# ─────────────────────────────────────────────
@app.get("/api/history/{target:path}")
async def get_history(target: str, limit: int = 20):
    supabase = get_supabase()
    result = supabase.table("scans").select(
        "id, scan_type, target, status, risk_score, created_at, completed_at"
    ).eq("target", target).eq("status", "done").order(
        "created_at", desc=True
    ).limit(limit).execute()
    return {"history": result.data}

# ─────────────────────────────────────────────
# GET /api/report/{scan_id}
# ─────────────────────────────────────────────
@app.get("/api/report/{scan_id}")
async def get_report(scan_id: str):
    """Get full scan report for Results / SharedReport pages."""
    supabase = get_supabase()
    scan = supabase.table("scans").select("*").eq("id", scan_id).single().execute()
    if not scan.data:
        raise HTTPException(404, "Scan not found")
    findings = supabase.table("findings").select("*").eq("scan_id", scan_id).execute()
    return {
        "scan": scan.data,
        "findings": findings.data,
    }

# ─────────────────────────────────────────────
# GET /api/report/{scan_id}/pdf
# ─────────────────────────────────────────────
@app.get("/api/report/{scan_id}/pdf")
async def get_report_pdf(scan_id: str):
    supabase = get_supabase()
    scan = supabase.table("scans").select("*").eq("id", scan_id).single().execute()
    if not scan.data:
        raise HTTPException(404, "Scan not found")

    findings = supabase.table("findings").select("*").eq("scan_id", scan_id).execute()
    scan_data = scan.data
    findings_data = findings.data

    # If PDF already generated, return existing URL
    if scan_data.get("pdf_url"):
        return {"pdf_url": scan_data["pdf_url"]}

    # Generate PDF
    pdf_bytes = generate_pdf(scan_data, findings_data)
    file_path = f"{scan_id}.pdf"

    # Upload to Supabase Storage "reports" bucket
    supabase.storage.from_("reports").upload(
        file_path, pdf_bytes, {"content-type": "application/pdf"}
    )
    public_url = supabase.storage.from_("reports").get_public_url(file_path)

    # Update scan record
    supabase.table("scans").update({"pdf_url": public_url}).eq("id", scan_id).execute()

    return {"pdf_url": public_url}
