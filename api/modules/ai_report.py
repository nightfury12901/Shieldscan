"""
Groq AI report generator.
Converts raw scan findings to plain-English report using LLaMA 3.
"""
import os
import json
import httpx

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"

SYSTEM_PROMPT = """You are a senior AppSec engineer advising a developer.
For EACH finding write:
1. WHAT IS THE PROBLEM — one clear sentence.
2. WHAT CAN AN ATTACKER DO — real-world impact.
3. HOW TO FIX IT — A detailed, numbered list of exact technical steps the developer must take to fix the vulnerability. Use Markdown for code blocks or file names.
4. HOW URGENT — CRITICAL / MEDIUM / LOW

After all findings, write a 2-sentence EXECUTIVE SUMMARY in plain English."""


async def generate_ai_report(findings: list[dict]) -> dict:
    api_key = os.getenv("GROQ_API_KEY", "")
    if not api_key:
        return _fallback_report(findings)
    if not findings:
        return {"executive_summary": "No significant security issues were found.", "findings": []}

    severity_order = {"critical": 0, "medium": 1, "low": 2}
    top_findings = sorted(findings, key=lambda f: severity_order.get(f.get("severity", "low"), 2))[:20]
    prompt_data = json.dumps([{
        "title": f.get("title", ""), "category": f.get("category", ""),
        "severity": f.get("severity", ""), "affected_asset": f.get("affected_asset", ""),
        "description": f.get("description", "")[:200],
    } for f in top_findings], indent=2)

    for model in ["llama-3.3-70b-versatile", "llama-3.1-8b-instant"]:
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(
                    GROQ_API_URL,
                    headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                    json={
                        "model": model,
                        "messages": [
                            {"role": "system", "content": SYSTEM_PROMPT},
                            {"role": "user", "content": f"Findings:\n\n{prompt_data}"},
                        ],
                        "max_tokens": 2048,
                        "temperature": 0.3,
                    }
                )
                if resp.status_code == 200:
                    content = resp.json()["choices"][0]["message"]["content"]
                    return {
                        "executive_summary": _extract_executive_summary(content),
                        "full_report": content,
                        "model_used": model,
                    }
                elif resp.status_code == 429:
                    continue
        except Exception:
            continue

    return _fallback_report(findings)


def _extract_executive_summary(text: str) -> str:
    lines = text.split("\n")
    in_summary = False
    summary = []
    for line in lines:
        if "executive summary" in line.lower():
            in_summary = True
            continue
        if in_summary and line.strip():
            summary.append(line.strip())
            if len(summary) >= 2:
                break
    return " ".join(summary) if summary else text[:300]


def _fallback_report(findings: list[dict]) -> dict:
    critical = sum(1 for f in findings if f.get("severity") == "critical")
    medium = sum(1 for f in findings if f.get("severity") == "medium")
    if critical:
        summary = f"Your site has {critical} critical issue(s) needing immediate attention — these could allow attackers to steal customer data or take over your systems."
    elif medium:
        summary = f"Your site has {medium} moderate issue(s) to address this week — they represent real but non-immediate risks."
    else:
        summary = "No significant security issues were found. Keep software updated and monitor regularly."
    return {"executive_summary": summary, "full_report": None, "model_used": "fallback"}
