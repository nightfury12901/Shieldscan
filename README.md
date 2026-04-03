# ShieldScan — Cybersecurity Audit Tool

A powerful, production-ready full-stack cybersecurity audit tool for small businesses.
Tagline: "One URL. One Click. One Report."

## Features

- **Three First-Class Scan Types**:
  - `URL`: Parallel scanning across 9 modules (SSL, Headers, DNS, Ports, CMS Vulnerabilities, Breach, Blacklist, CVE, XSS/SQLi).
  - `GitHub`: Static analysis across repository files for secrets, CVE dependencies, insecure configs, and code patterns.
  - `ZIP`: Equivalent static code analysis on an uploaded source code boundary.
- **AI-Powered Plain English Reports**: Groq (LLaMA 3) converts raw JSON findings into an executive summary and readable reports.
- **Risk Scoring**: Deterministic Business Risk Score (0-100) using spec-defined weighting.
- **Live Progress**: Animated frontend with real-time updates via Supabase Realtime subscriptions.
- **PDF Export**: Dynamically generated branded PDF reports using `reportlab`.

## Tech Stack

- **Frontend**: React + Tailwind CSS (Vite), intended for Vercel Static deployment.
- **Backend**: Python FastAPI as Vercel Serverless Functions (`/api/*`).
- **Database / Auth**: Supabase (PostgreSQL, Auth UI, Realtime, Storage).

## Setup Instructions

### 1. Supabase Initialization
1. Create a Supabase project at [supabase.com](https://supabase.com).
2. Run the SQL script located in `/supabase/migrations/001_init.sql` in the Supabase SQL Editor.
3. Enable **Email/Password** and **Google OAuth** in Authentication.
4. Set up the required buckets and Realtime via the migration script (automatic if script is run successfully).

### 2. Environment Variables
1. Copy `.env.example` to `.env`.
2. Fill in the keys:
   - `SUPABASE_URL`, `SUPABASE_ANON_KEY`, `SUPABASE_SERVICE_ROLE_KEY`
   - `GROQ_API_KEY` (Free tier works perfectly)
   - `HIBP_API_KEY` (Optional for credential leak check)
   - `GOOGLE_SAFE_BROWSING_API_KEY` (Optional)
   - `WPSCAN_API_KEY` (Optional)
   - `NVD_API_KEY` (Optional, prevents rate-limits on CVE lookup)
   - `ZAP_API_URL` (Optional, if omitted, a pure-Python placeholder checks for XSS/SQLi)
3. Copy the `VITE_` prefixed variables into `frontend/.env`.

### 3. Local Development

Start the backend:
```bash
uvicorn api.index:app --reload
```

Start the frontend (in a separate terminal):
```bash
cd frontend
npm install
npm run dev
```

### 4. Vercel Deployment (100% Serverless)
This repository is pre-configured to deploy seamlessly to Vercel via the `vercel.json` file. 

1. Install the Vercel CLI or deploy via the Vercel Dashboard.
2. The config ensures `/api/*` routes use `@vercel/python` (FastAPI) and the rest fallback to `@vercel/static` (React SPA).
3. Be sure to insert your environment variables in the Vercel Project Settings.

---

**Note on Constraints in Serverless**:
- **OWASP ZAP**: By default, the `zap_scan.py` module uses a fast, pure-Python placeholder to check for Reflected XSS and SQLi. You can run a real ZAP daemon elsewhere and pass its URL via `ZAP_API_URL`.
- **Port Scanner**: The scanner utilizes native `asyncio.open_connection()` with a tight timeout instead of Nmap bindings since standard nmap binaries are unavailable in Vercel lambda execution environments. 
