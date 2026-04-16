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
from modules.ai_report import generate_ai_report, GROQ_API_URL
from modules.pdf_report import generate_pdf
from modules.webhook import send_slack_webhook
from modules.github_pr import generate_github_autofix_pr
# ── New modules ────────────────────────────────────────────────────
from modules.cookie_scan import scan_cookies
from modules.robots_scan import scan_robots
from modules.supply_chain_scan import scan_supply_chain
from modules.rate_limit_scan import scan_rate_limiting
from modules.open_redirect_scan import scan_open_redirects
from modules.lookalike_domain_scan import scan_lookalike_domains
from modules.payment import (
    create_order, verify_payment, apply_promo, decrement_credits,
    CreateOrderRequest, VerifyPaymentRequest, ApplyPromoRequest
)

# ─────────────────────────────────────────────
# App setup
# ─────────────────────────────────────────────
app = FastAPI(title="ShieldScan API", version="2.0.0")

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
    scan_id: Optional[str] = None  # Pre-created by frontend for instant navigation

class GithubScanRequest(BaseModel):
    repo_url: str
    github_pat: Optional[str] = None
    user_id: Optional[str] = None
    webhook_url: Optional[str] = None
    scan_id: Optional[str] = None  # Pre-created by frontend for instant navigation

class ZipScanRequest(BaseModel):
    storage_path: str
    user_id: Optional[str] = None
    webhook_url: Optional[str] = None
    scan_id: Optional[str] = None  # Pre-created by frontend for instant navigation

class AutoFixGenerateRequest(BaseModel):
    scan_id: str
    finding_id: str
    github_pat: str

class AutoFixPRRequest(BaseModel):
    scan_id: str
    finding_id: str
    github_pat: str
    new_content: str  # User-reviewed / edited content

class ChatRequest(BaseModel):
    finding_id: str
    message: str
    history: Optional[list[dict]] = []  # [{role: "user"|"assistant", content: "..."}]

class FixedFileRequest(BaseModel):
    scan_id: str
    finding_id: str

# ─────────────────────────────────────────────
# HEALTH CHECK
# ─────────────────────────────────────────────
@app.get("/api/health")
async def health():
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat(), "version": "2.0.0"}

# ─────────────────────────────────────────────
# POST /api/scan/url
# ─────────────────────────────────────────────
@app.post("/api/scan/url")
async def scan_url(req: UrlScanRequest):
    url = validate_url(req.url)
    if not req.user_id:
        raise HTTPException(401, "User ID required to scan")

    # Deduct credit server-side (security: never trust client to skip this)
    decrement_credits(req.user_id)

    supabase = get_supabase()

    if req.scan_id:
        # Frontend pre-created the row — just mark it as running
        scan_id = req.scan_id
        supabase.table("scans").update({"status": "running", "progress": 0}).eq("id", scan_id).execute()
    else:
        # Fallback: create row here (legacy / direct API callers)
        scan_row = supabase.table("scans").insert({
            "user_id": req.user_id,
            "scan_type": "url",
            "target": url,
            "status": "running",
            "progress": 0,
        }).execute()
        scan_id = scan_row.data[0]["id"]

    # Run synchronously — Vercel kills background_tasks after response is sent.
    # maxDuration=60 keeps this request alive while the scan completes.
    await _run_url_scan(scan_id, url, req.webhook_url)
    return {"scan_id": scan_id, "status": "done"}

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
        await update_progress(scan_id, 10)

        # ── Batch 1: fast modules (timeout ≤ 15s each) ──────────────
        fast_results = await asyncio.gather(
            run_module("headers",       scan_headers(url),          timeout=12),
            run_module("ssl",           scan_ssl(url),              timeout=12),
            run_module("dns",           scan_dns(url),              timeout=12),
            run_module("cms",           scan_cms(url),              timeout=12),
            run_module("breach",        check_breach(url),          timeout=12),
            run_module("blacklist",     check_blacklist(url),       timeout=12),
            run_module("cve",           lookup_cves(url),           timeout=12),
            run_module("cookies",       scan_cookies(url),          timeout=12),
            run_module("robots",        scan_robots(url),           timeout=12),
        )
        await update_progress(scan_id, 50)

        # ── Batch 2: slow/active modules (capped at 15s each) ───────
        slow_results = await asyncio.gather(
            run_module("ports",         scan_ports(url),            timeout=15),
            run_module("zap",           scan_zap(url),              timeout=15),
            run_module("supply_chain",  scan_supply_chain(url),     timeout=15),
            run_module("rate_limit",    scan_rate_limiting(url),    timeout=15),
            run_module("open_redirect", scan_open_redirects(url),   timeout=15),
            run_module("lookalike",     scan_lookalike_domains(url),timeout=15),
        )
        await update_progress(scan_id, 80)

        results = list(fast_results) + list(slow_results)
        module_statuses = {}
        all_findings = []
        for r in results:
            module_statuses[r["module"]] = r["status"]
            all_findings.extend(r.get("findings", []))

        risk_score = compute_risk_score(all_findings)
        ai_report = await generate_ai_report(all_findings)

        # Deduplicate URL findings based on title and severity
        unique_findings = []
        seen = set()
        for f in all_findings:
            sig = f"{f.get('title')}:{f.get('severity')}"
            if sig not in seen:
                seen.add(sig)
                unique_findings.append(f)

        await update_progress(scan_id, 95)
        insert_findings(scan_id, unique_findings)

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
# POST /api/autofix/generate  (Step 1 — AI generates patch, no PR yet)
# ─────────────────────────────────────────────
import httpx

@app.post("/api/autofix/generate")
async def autofix_generate(req: AutoFixGenerateRequest):
    supabase = get_supabase()

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

    file_path = finding.get("affected_asset", "").lstrip("/")
    if not file_path or ":" in file_path:
        raise HTTPException(400, "Finding does not have a clearly patchable file path.")

    repo_url = scan["target"]
    from urllib.parse import urlparse
    path_parts = urlparse(repo_url).path.strip("/").split("/")
    owner = path_parts[0]
    repo = path_parts[1] if len(path_parts) > 1 else ""
    if repo.endswith(".git"):
        repo = repo[:-4]

    groq_api_key = os.getenv("GROQ_API_KEY")
    if not groq_api_key:
        raise HTTPException(500, "Groq API key not configured")

    gh_headers = {
        "Authorization": f"Bearer {req.github_pat}",
        "Accept": "application/vnd.github.v3.raw",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        # Fetch raw file content
        resp = await client.get(
            f"https://api.github.com/repos/{owner}/{repo}/contents/{file_path}",
            headers=gh_headers,
        )
        if resp.status_code != 200:
            raise HTTPException(400, f"Cannot fetch file from GitHub: {resp.text[:300]}")

        original_content = resp.text

        # AI Rewrite prompt
        prompt = (
            f"You are an expert security engineer fixing a vulnerability in '{file_path}'.\n\n"
            f"VULNERABILITY: {finding['title']}\n{finding['description']}\n\n"
            f"DIRECTIONS: {finding['fix_steps']}\n\n"
            f"ORIGINAL CODE:\n```\n{original_content}\n```\n\n"
            "REWRITE THE ENTIRE FILE. Return ONLY the complete, fully patched source code. "
            "Do NOT return just a snippet. Do NOT wrap in markdown backticks. Return RAW code only."
        )

        ai_resp = await client.post(
            GROQ_API_URL,
            headers={"Authorization": f"Bearer {groq_api_key}", "Content-Type": "application/json"},
            json={
                "model": "llama-3.3-70b-versatile",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1,
            },
        )
        if ai_resp.status_code != 200:
            raise HTTPException(500, f"AI fix generation failed: {ai_resp.text[:300]}")

        new_content = ai_resp.json()["choices"][0]["message"]["content"].strip()
        # Strip markdown fences if AI misbehaved
        if new_content.startswith("```"):
            lines = new_content.split("\n")
            new_content = "\n".join(lines[1:-1]) if len(lines) > 2 else new_content

    return {
        "status": "ok",
        "original_content": original_content,
        "new_content": new_content,
        "file_path": file_path,
        "scan_id": req.scan_id,
        "finding_id": req.finding_id,
    }


# ─────────────────────────────────────────────
# POST /api/autofix/pr  (Step 2 — user-approved content → create PR)
# ─────────────────────────────────────────────
@app.post("/api/autofix/pr")
async def autofix_create_pr(req: AutoFixPRRequest):
    supabase = get_supabase()

    finding_res = supabase.table("findings").select("*").eq("id", req.finding_id).execute()
    if not finding_res.data:
        raise HTTPException(404, "Finding not found")
    finding = finding_res.data[0]

    scan_res = supabase.table("scans").select("*").eq("id", req.scan_id).execute()
    if not scan_res.data:
        raise HTTPException(404, "Scan not found")
    scan = scan_res.data[0]

    file_path = finding.get("affected_asset", "").lstrip("/")

    try:
        pr_url = await generate_github_autofix_pr(
            repo_url=scan["target"],
            pat=req.github_pat,
            file_path=file_path,
            new_content=req.new_content,
            title=finding["title"],
            description=finding["description"],
        )
        return {"status": "ok", "pr_url": pr_url}
    except Exception as e:
        raise HTTPException(500, str(e))


# ─────────────────────────────────────────────
# POST /api/chat  (Per-finding AI assistant)
# ─────────────────────────────────────────────
@app.post("/api/chat")
async def chat(req: ChatRequest):
    supabase = get_supabase()
    groq_api_key = os.getenv("GROQ_API_KEY")
    if not groq_api_key:
        raise HTTPException(500, "Groq API key not configured")

    # Load finding context
    finding_res = supabase.table("findings").select("*").eq("id", req.finding_id).execute()
    finding = finding_res.data[0] if finding_res.data else {}

    system_prompt = (
        "You are ShieldBot, an expert application security engineer working inside the ShieldScan platform. "
        "You are helping a developer or business owner understand and fix a specific security vulnerability "
        "that was found in their web application or codebase.\n\n"
        f"VULNERABILITY CONTEXT:\n"
        f"- Title: {finding.get('title', 'Unknown')}\n"
        f"- Severity: {finding.get('severity', 'unknown').upper()}\n"
        f"- Category: {finding.get('category', 'unknown')}\n"
        f"- Affected Asset: {finding.get('affected_asset', 'N/A')}\n"
        f"- Description: {finding.get('description', 'N/A')}\n"
        f"- Suggested Fix: {finding.get('fix_steps', 'N/A')}\n\n"
        "Answer questions clearly and helpfully. For non-technical users, explain concepts simply. "
        "For developers, provide specific code examples. Never make up CVE numbers or statistics. "
        "Keep responses concise — under 300 words unless a detailed code example is needed."
    )

    messages = [{"role": "system", "content": system_prompt}]
    # Add conversation history
    for h in (req.history or []):
        if h.get("role") in ("user", "assistant") and h.get("content"):
            messages.append({"role": h["role"], "content": h["content"]})
    # Add current message
    messages.append({"role": "user", "content": req.message})

    async with httpx.AsyncClient(timeout=20) as client:
        resp = await client.post(
            GROQ_API_URL,
            headers={"Authorization": f"Bearer {groq_api_key}", "Content-Type": "application/json"},
            json={
                "model": "llama-3.3-70b-versatile",
                "messages": messages,
                "temperature": 0.4,
                "max_tokens": 600,
            },
        )
        if resp.status_code != 200:
            raise HTTPException(500, f"AI service error: {resp.text[:200]}")

        reply = resp.json()["choices"][0]["message"]["content"]
        return {"reply": reply}


# ─────────────────────────────────────────────
# POST /api/scan/github
# ─────────────────────────────────────────────
@app.post("/api/scan/github")
async def scan_github(req: GithubScanRequest):
    repo_url = validate_github_url(req.repo_url)
    if not req.user_id:
        raise HTTPException(401, "User ID required to scan")

    decrement_credits(req.user_id)

    supabase = get_supabase()

    if req.scan_id:
        scan_id = req.scan_id
        supabase.table("scans").update({"status": "running", "progress": 0}).eq("id", scan_id).execute()
    else:
        scan_row = supabase.table("scans").insert({
            "user_id": req.user_id,
            "scan_type": "github",
            "target": repo_url,
            "status": "running",
            "progress": 0,
        }).execute()
        scan_id = scan_row.data[0]["id"]

    await _run_github_scan(scan_id, repo_url, req.github_pat, req.webhook_url)
    return {"scan_id": scan_id, "status": "done"}

async def _run_github_scan(scan_id: str, repo_url: str, pat: Optional[str], webhook_url: Optional[str] = None):
    supabase = get_supabase()
    try:
        await update_progress(scan_id, 10)
        files = await _fetch_github_files(repo_url, pat)
        await update_progress(scan_id, 20)

        results = await asyncio.gather(
            run_module("secrets",       scan_secrets(files)),
            run_module("dependencies",  scan_dependencies(files)),
            run_module("code_patterns", scan_code_patterns(files)),
            run_module("config_files",  scan_config_files(files)),
            run_module("auth_issues",   scan_auth_issues(files)),
            return_exceptions=True
        )

        valid_results = [r for r in results if not isinstance(r, Exception) and isinstance(r, dict)]

        await update_progress(scan_id, 80)

        all_findings = []
        module_statuses = {}
        for r in valid_results:
            module_statuses[r.get("module", "unknown")] = r.get("status", "unknown")
            all_findings.extend(r.get("findings", []))

        risk_score = compute_risk_score(all_findings)
        ai_report = await generate_ai_report(all_findings)

        # Deduplicate findings based on title, affected_asset, and severity
        unique_findings = []
        seen = set()
        for f in all_findings:
            # Create a unique signature for each finding to prevent duplicates
            sig = f"{f.get('title')}:{f.get('affected_asset')}:{f.get('severity')}"
            if sig not in seen:
                seen.add(sig)
                unique_findings.append(f)

        await update_progress(scan_id, 95)
        insert_findings(scan_id, unique_findings)

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
    import base64
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
        repo_resp = await client.get(f"https://api.github.com/repos/{owner}/{repo}", headers=headers)
        if repo_resp.status_code != 200:
            raise HTTPException(400, f"GitHub repo not found or not accessible: {repo_resp.status_code}")
        default_branch = repo_resp.json().get("default_branch", "main")

        tree_resp = await client.get(
            f"https://api.github.com/repos/{owner}/{repo}/git/trees/{default_branch}?recursive=1",
            headers=headers,
        )
        if tree_resp.status_code != 200:
            raise HTTPException(400, "Could not fetch repository tree")

        tree = tree_resp.json().get("tree", [])
        interesting = [
            f for f in tree
            if f["type"] == "blob" and f.get("size", 0) < 500_000
            and not any(skip in f["path"] for skip in [".min.js", "node_modules", ".git", "vendor/"])
        ][:200]

        for i in range(0, len(interesting), 20):
            batch = interesting[i:i+20]
            tasks = [
                client.get(
                    f"https://api.github.com/repos/{owner}/{repo}/contents/{file_info['path']}?ref={default_branch}",
                    headers=headers,
                )
                for file_info in batch
            ]
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            for file_info, resp in zip(batch, responses):
                if isinstance(resp, Exception):
                    continue
                if resp.status_code == 200:
                    data = resp.json()
                    content_b64 = data.get("content", "")
                    if content_b64:
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
async def scan_zip(req: ZipScanRequest):
    if not req.user_id:
        raise HTTPException(401, "User ID required to scan")

    decrement_credits(req.user_id)

    supabase = get_supabase()

    if req.scan_id:
        scan_id = req.scan_id
        supabase.table("scans").update({"status": "running", "progress": 0}).eq("id", scan_id).execute()
    else:
        scan_row = supabase.table("scans").insert({
            "user_id": req.user_id,
            "scan_type": "zip",
            "target": req.storage_path,
            "status": "running",
            "progress": 0,
        }).execute()
        scan_id = scan_row.data[0]["id"]

    await _run_zip_scan(scan_id, req.storage_path)
    return {"scan_id": scan_id, "status": "done"}

async def _run_zip_scan(scan_id: str, storage_path: str):
    import zipfile, tempfile, shutil, pathlib
    supabase = get_supabase()
    tmp_dir = None
    try:
        await update_progress(scan_id, 5)
        signed = supabase.storage.from_("zip-uploads").create_signed_url(
            storage_path.replace("zip-uploads/", ""), 300
        )
        signed_url = signed.get("signedURL") or signed.get("signedUrl")
        if not signed_url:
            raise ValueError("Could not get signed URL for ZIP")

        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(signed_url)
            zip_bytes = resp.content

        await update_progress(scan_id, 15)

        if not zip_bytes[:4] == b"PK\x03\x04":
            raise ValueError("Invalid ZIP file (bad magic bytes)")

        tmp_dir = tempfile.mkdtemp(prefix="shieldscan_")
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            for member in zf.namelist():
                if ".." in member or member.startswith("/") or member.startswith("\\"):
                    continue
                member_path = pathlib.Path(tmp_dir) / member
                if not str(member_path).startswith(tmp_dir):
                    continue
                zf.extract(member, tmp_dir)

        await update_progress(scan_id, 20)

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

        results = await asyncio.gather(
            run_module("secrets",       scan_secrets(files)),
            run_module("dependencies",  scan_dependencies(files)),
            run_module("code_patterns", scan_code_patterns(files)),
            run_module("config_files",  scan_config_files(files)),
            run_module("auth_issues",   scan_auth_issues(files)),
            return_exceptions=True
        )

        # Filter out Exceptions if any module timed out
        valid_results = [r for r in results if not isinstance(r, Exception) and isinstance(r, dict)]

        await update_progress(scan_id, 80)

        all_findings = []
        module_statuses = {}
        for r in valid_results:
            module_statuses[r.get("module", "unknown")] = r.get("status", "unknown")
            all_findings.extend(r.get("findings", []))

        risk_score = compute_risk_score(all_findings)
        ai_report = await generate_ai_report(all_findings)
        
        # Deduplicate findings based on title, affected_asset, and severity
        unique_findings = []
        seen = set()
        for f in all_findings:
            # Create a unique signature for each finding to prevent duplicates
            sig = f"{f.get('title')}:{f.get('affected_asset')}:{f.get('severity')}"
            if sig not in seen:
                seen.add(sig)
                unique_findings.append(f)
                
        await update_progress(scan_id, 95)
        insert_findings(scan_id, unique_findings)

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
        if tmp_dir and os.path.exists(tmp_dir):
            try:
                import shutil
                shutil.rmtree(tmp_dir)
            except Exception:
                pass

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

    if scan_data.get("pdf_url"):
        return {"pdf_url": scan_data["pdf_url"]}

    pdf_bytes = generate_pdf(scan_data, findings_data)
    file_path = f"{scan_id}.pdf"

    supabase.storage.from_("reports").upload(
        file_path, pdf_bytes, {"content-type": "application/pdf"}
    )
    public_url = supabase.storage.from_("reports").get_public_url(file_path)

    supabase.table("scans").update({"pdf_url": public_url}).eq("id", scan_id).execute()

    return {"pdf_url": public_url}

# ─────────────────────────────────────────────
# PAYMENT & FREEMIUM APIs
# ─────────────────────────────────────────────
@app.get("/api/credits")
async def get_user_credits(user_id: str):
    supabase = get_supabase()
    res = supabase.table("user_credits").select("scans_remaining").eq("user_id", user_id).execute()
    if not res.data:
        try:
            supabase.table("user_credits").insert({
                "user_id": user_id,
                "scans_remaining": 3
            }).execute()
            return {"scans_remaining": 3}
        except Exception:
            return {"scans_remaining": 0}
    return {"scans_remaining": res.data[0]["scans_remaining"]}

@app.post("/api/payment/create-order")
async def handle_create_order(req: CreateOrderRequest):
    return create_order(req)

@app.post("/api/payment/verify")
async def handle_verify_payment(req: VerifyPaymentRequest):
    return verify_payment(req)

@app.post("/api/payment/apply-promo")
async def handle_apply_promo(req: ApplyPromoRequest):
    return apply_promo(req)

# ─────────────────────────────────────────────
# POST /api/remediate/fixed-file
# For ZIP scans: re-fetches the offending file, AI-rewrites it with
# ${ENV_VAR_NAME} placeholders in place of real secrets, returns for download.
# ─────────────────────────────────────────────
@app.post("/api/remediate/fixed-file")
async def get_fixed_file(req: FixedFileRequest):
    import zipfile, io as _io

    supabase = get_supabase()
    groq_api_key = os.getenv("GROQ_API_KEY")
    if not groq_api_key:
        raise HTTPException(500, "Groq API key not configured")

    # Load the finding
    finding_res = supabase.table("findings").select("*").eq("id", req.finding_id).execute()
    if not finding_res.data:
        raise HTTPException(404, "Finding not found")
    finding = finding_res.data[0]

    # Load the scan (must be a zip scan)
    scan_res = supabase.table("scans").select("*").eq("id", req.scan_id).execute()
    if not scan_res.data:
        raise HTTPException(404, "Scan not found")
    scan = scan_res.data[0]

    if scan["scan_type"] != "zip":
        raise HTTPException(400, "Fixed-file download is only available for ZIP scans.")

    file_path = (finding.get("affected_asset") or "").replace("\\", "/").lstrip("/")
    if not file_path:
        raise HTTPException(400, "This finding has no associated file to fix.")

    # Re-download the original ZIP from Supabase storage
    storage_path = scan["target"].replace("zip-uploads/", "")
    try:
        signed = supabase.storage.from_("zip-uploads").create_signed_url(storage_path, 120)
        signed_url = signed.get("signedURL") or signed.get("signedUrl")
        if not signed_url:
            raise ValueError("Cannot generate signed URL")
    except Exception as e:
        raise HTTPException(500, f"Could not access original ZIP: {e}")

    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(signed_url)
        if resp.status_code != 200:
            raise HTTPException(500, "Failed to download original ZIP file")
        zip_bytes = resp.content

    # Extract only the target file from the ZIP
    original_content: str | None = None
    try:
        with zipfile.ZipFile(_io.BytesIO(zip_bytes)) as zf:
            # Flexible matching: strip top-level directory prefix if present
            for name in zf.namelist():
                norm = name.replace("\\", "/").lstrip("/")
                # Match either exact path or path without leading directory
                if norm == file_path or norm.endswith("/" + file_path) or file_path.endswith("/" + norm.split("/", 1)[-1]):
                    original_content = zf.read(name).decode("utf-8", errors="ignore")
                    break
    except Exception as e:
        raise HTTPException(500, f"Could not read file from ZIP: {e}")

    if original_content is None:
        raise HTTPException(404, f"File '{file_path}' not found inside the uploaded ZIP.")

    # Build a category-aware prompt so the AI applies the RIGHT fix strategy
    category = finding.get("category", "")
    title    = finding.get("title", "")
    fix_hint = finding.get("fix_steps", "")

    # Determine fix strategy based on vulnerability category
    if category in ("hardcoded_secret", "exposed_env", "potential_secret", "exposed_config"):
        strategy = (
            "STRATEGY — Secrets / Credentials:\n"
            "  • Replace every hardcoded secret, API key, password, or token with a ${ENV_VAR_NAME} "
            "placeholder (or process.env.VAR_NAME for JS/TS) using the most descriptive name possible.\n"
            "  • Example: DB_PASSWORD=hunter2  →  DB_PASSWORD=${DB_PASSWORD}\n"
            "  • Example: const key = 'sk-abc' →  const key = process.env.OPENAI_KEY\n"
            "  • Add a comment near each placeholder explaining what value should be set.\n"
            "  • Keep ALL other file content (comments, structure, logic) exactly as-is."
        )
    elif category in ("sql_injection", "injection"):
        strategy = (
            "STRATEGY — SQL Injection:\n"
            "  • Replace all raw string-concatenated SQL queries with parameterised queries / prepared statements.\n"
            "  • Use the correct syntax for the detected language/library (e.g. cursor.execute(sql, params) for Python, "
            "? placeholders for JDBC, $1/$2 for pg in Node.js).\n"
            "  • Never interpolate user-controlled values directly into SQL strings.\n"
            "  • Keep query logic, column names and table names identical — only fix the parameterisation."
        )
    elif category in ("xss", "cross_site_scripting"):
        strategy = (
            "STRATEGY — Cross-Site Scripting (XSS):\n"
            "  • Escape all user-supplied data before it is inserted into HTML output.\n"
            "  • Use the appropriate escaping function for the language (e.g. html.escape() in Python, "
            "DOMPurify.sanitize() or textContent in JS, htmlspecialchars() in PHP).\n"
            "  • Add or tighten the Content-Security-Policy header if this is a server config file.\n"
            "  • Do NOT use innerHTML or dangerouslySetInnerHTML with un-sanitised input."
        )
    elif category in ("open_redirect",):
        strategy = (
            "STRATEGY — Open Redirect:\n"
            "  • Add an allowlist of valid redirect destinations; reject or strip any URL that is not on the list.\n"
            "  • Never use raw user input as the target of a Location header or window.location assignment without validation.\n"
            "  • For relative redirects, strip the scheme and host so the redirect stays on the same origin."
        )
    elif category in ("auth_issue", "authentication", "weak_auth", "session"):
        strategy = (
            "STRATEGY — Authentication / Session Security:\n"
            "  • Fix the specific auth weakness described (e.g. add password hashing with bcrypt/argon2, "
            "enforce HTTPS-only cookies, set secure session flags, prevent credential exposure in logs).\n"
            "  • Do not weaken any existing security controls while applying the fix.\n"
            "  • Replace any plaintext secrets with ${ENV_VAR_NAME} references."
        )
    elif category in ("dependency", "vulnerable_dependency"):
        strategy = (
            "STRATEGY — Vulnerable Dependency:\n"
            "  • Update the pinned version of the flagged package to the latest non-vulnerable version.\n"
            "  • If the file is package.json, requirements.txt, pyproject.toml, Gemfile, etc., update ONLY "
            "the affected package version; leave all other dependencies untouched.\n"
            "  • Add a comment noting why the version was bumped."
        )
    elif category in ("missing_header", "security_header"):
        strategy = (
            "STRATEGY — Missing Security Headers:\n"
            "  • Add the missing HTTP security headers (e.g. Content-Security-Policy, X-Frame-Options, "
            "Strict-Transport-Security, X-Content-Type-Options, Referrer-Policy) to the server config or middleware.\n"
            "  • Use secure, production-ready values for each header.\n"
            "  • Do not remove or weaken any existing headers."
        )
    elif category in ("cors",):
        strategy = (
            "STRATEGY — CORS Misconfiguration:\n"
            "  • Replace wildcard (*) Allow-Origin values with an explicit allowlist of trusted origins.\n"
            "  • Ensure credentials are not allowed alongside wildcard origins.\n"
            "  • Tighten allowed methods and headers to only what is strictly required."
        )
    else:
        # Universal fallback — let the AI use its judgement guided by the fix_steps
        strategy = (
            "STRATEGY — General Security Fix:\n"
            "  • Apply the fix described in the SUGGESTED FIX section below.\n"
            "  • If the fix requires moving secrets to environment variables, use ${ENV_VAR_NAME} placeholders.\n"
            "  • If the fix requires code changes (sanitisation, parameterisation, header additions, etc.), "
            "apply the minimal correct change without altering unrelated logic.\n"
            "  • Keep ALL other file content (comments, structure, imports) identical unless they are "
            "directly part of the vulnerability."
        )

    prompt = (
        f"You are an expert application security engineer producing a FIXED version of a source file.\n\n"
        f"FILE: {file_path}\n\n"
        f"VULNERABILITY FOUND:\n"
        f"  Title:    {title}\n"
        f"  Category: {category}\n"
        f"  Detail:   {finding['description']}\n\n"
        f"SUGGESTED FIX:\n{fix_hint}\n\n"
        f"{strategy}\n\n"
        f"ABSOLUTE RULES (never break these):\n"
        f"  1. Return ONLY the raw, complete file content — no markdown fences, no explanations.\n"
        f"  2. Rewrite the ENTIRE file (not just the affected lines) so the user can drop it\n"
        f"     straight into their project.\n"
        f"  3. Preserve the original file encoding, indentation style, and line endings.\n"
        f"  4. Do NOT introduce new bugs or remove unrelated functionality.\n\n"
        f"ORIGINAL FILE CONTENT:\n{original_content}"
    )

    async with httpx.AsyncClient(timeout=30) as client:
        ai_resp = await client.post(
            GROQ_API_URL,
            headers={"Authorization": f"Bearer {groq_api_key}", "Content-Type": "application/json"},
            json={
                "model": "llama-3.3-70b-versatile",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.05,
                "max_tokens": 4096,
            },
        )
        if ai_resp.status_code != 200:
            raise HTTPException(500, f"AI service error: {ai_resp.text[:200]}")

    fixed_content = ai_resp.json()["choices"][0]["message"]["content"].strip()
    # Strip accidental markdown fences
    if fixed_content.startswith("```"):
        lines = fixed_content.split("\n")
        fixed_content = "\n".join(lines[1:-1]) if len(lines) > 2 else fixed_content

    filename = file_path.split("/")[-1]
    return {
        "status": "ok",
        "filename": filename,
        "file_path": file_path,
        "content": fixed_content,
    }
