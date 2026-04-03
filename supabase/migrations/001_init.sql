-- ============================================================
-- ShieldScan — Supabase Migration 001: Initial Schema
-- Run this in Supabase SQL Editor or via supabase db push
-- ============================================================

-- ─────────────────────────────────────────────
-- SCANS
-- ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scans (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id       UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  scan_type     TEXT NOT NULL CHECK (scan_type IN ('url', 'github', 'zip')),
  target        TEXT NOT NULL,
  status        TEXT NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending', 'running', 'done', 'failed')),
  progress      INT DEFAULT 0 CHECK (progress >= 0 AND progress <= 100),
  risk_score    INT CHECK (risk_score >= 0 AND risk_score <= 100),
  raw_json      JSONB,
  ai_report     JSONB,
  pdf_url       TEXT,
  created_at    TIMESTAMPTZ DEFAULT now(),
  completed_at  TIMESTAMPTZ
);

-- ─────────────────────────────────────────────
-- FINDINGS
-- ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS findings (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id         UUID REFERENCES scans(id) ON DELETE CASCADE,
  severity        TEXT CHECK (severity IN ('critical', 'medium', 'low')),
  category        TEXT,
  title           TEXT,
  description     TEXT,
  fix_steps       TEXT,
  affected_asset  TEXT,
  line_number     INT,
  created_at      TIMESTAMPTZ DEFAULT now()
);

-- ─────────────────────────────────────────────
-- RATE LIMITS (for Edge Middleware)
-- ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS rate_limits (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ip         TEXT NOT NULL,
  scan_type  TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS rate_limits_ip_type_idx ON rate_limits (ip, scan_type, created_at);

-- ─────────────────────────────────────────────
-- SCAN HISTORY VIEW
-- ─────────────────────────────────────────────
CREATE OR REPLACE VIEW scan_history_view AS
  SELECT
    target AS domain,
    date_trunc('week', created_at) AS week,
    AVG(risk_score)::INT AS avg_score,
    COUNT(*) AS scan_count
  FROM scans
  WHERE status = 'done' AND risk_score IS NOT NULL
  GROUP BY target, week;

-- ─────────────────────────────────────────────
-- ROW LEVEL SECURITY
-- ─────────────────────────────────────────────
ALTER TABLE scans    ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE rate_limits ENABLE ROW LEVEL SECURITY;

-- scans: authenticated users see only their own
CREATE POLICY "Users see own scans"
  ON scans FOR SELECT
  USING (auth.uid() = user_id);

-- scans: authenticated users can update their own scans
CREATE POLICY "Users update own scans"
  ON scans FOR UPDATE
  USING (auth.uid() = user_id);

-- scans: anyone can insert (anonymous scans have user_id = NULL)
CREATE POLICY "Anyone can insert scan"
  ON scans FOR INSERT
  WITH CHECK (true);

-- scans: service role can do everything (for backend)
CREATE POLICY "Service role full access scans"
  ON scans FOR ALL
  USING (auth.role() = 'service_role');

-- findings: inherit from scan ownership
CREATE POLICY "Users see own findings"
  ON findings FOR SELECT
  USING (
    EXISTS (
      SELECT 1 FROM scans
      WHERE scans.id = findings.scan_id
        AND scans.user_id = auth.uid()
    )
  );

CREATE POLICY "Service role full access findings"
  ON findings FOR ALL
  USING (auth.role() = 'service_role');

-- rate_limits: service role only
CREATE POLICY "Service role full access rate_limits"
  ON rate_limits FOR ALL
  USING (auth.role() = 'service_role');

-- ─────────────────────────────────────────────
-- REALTIME
-- Enable realtime on scans table for progress updates
-- ─────────────────────────────────────────────
ALTER PUBLICATION supabase_realtime ADD TABLE scans;

-- ─────────────────────────────────────────────
-- STORAGE BUCKETS
-- Create via Supabase Dashboard or these SQL helpers
-- ─────────────────────────────────────────────
INSERT INTO storage.buckets (id, name, public, file_size_limit)
VALUES
  ('zip-uploads', 'zip-uploads', false, 52428800),  -- 50MB, private
  ('reports',     'reports',     true,  10485760)    -- 10MB, public
ON CONFLICT (id) DO NOTHING;

-- Allow authenticated + anonymous users to upload to zip-uploads
CREATE POLICY "Anyone can upload zip"
  ON storage.objects FOR INSERT
  WITH CHECK (bucket_id = 'zip-uploads');

-- Allow service role to read zip-uploads (for backend download)
CREATE POLICY "Service role reads zips"
  ON storage.objects FOR SELECT
  USING (bucket_id = 'zip-uploads' AND auth.role() = 'service_role');

-- Allow service role to delete from zip-uploads (cleanup)
CREATE POLICY "Service role deletes zips"
  ON storage.objects FOR DELETE
  USING (bucket_id = 'zip-uploads' AND auth.role() = 'service_role');

-- Allow public read of reports
CREATE POLICY "Public reads reports"
  ON storage.objects FOR SELECT
  USING (bucket_id = 'reports');

-- Allow service role to upload reports
CREATE POLICY "Service role uploads reports"
  ON storage.objects FOR INSERT
  WITH CHECK (bucket_id = 'reports' AND auth.role() = 'service_role');
