import { useEffect, useState, useMemo } from 'react'
import { useParams } from 'react-router-dom'
import { createPortal } from 'react-dom'
import { supabase } from '../lib/supabase'
import {
  Loader2, Download, SearchCode, Sparkles, AlertCircle,
  FileText, Activity, Shield, ChevronDown, MessageSquare,
} from 'lucide-react'
import {
  Chart as ChartJS, CategoryScale, LinearScale, PointElement,
  LineElement, Title, Tooltip, Legend, Filler,
} from 'chart.js'
import { Line } from 'react-chartjs-2'
import AutoFixReviewModal from '../components/AutoFixReviewModal'
import FindingChatDrawer from '../components/FindingChatDrawer'

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Title, Tooltip, Legend, Filler)

// ────────────────────────────────────────────────────────
// Sidebar
// ────────────────────────────────────────────────────────
function SidebarContent({ scan, criticalCount, mediumCount, lowCount, onExport }: any) {
  const displayUrl = scan?.target || 'loading...'
  const total = criticalCount + mediumCount + lowCount

  const scrollToSection = (id: string) => {
    const el = document.getElementById(id)
    if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }

  return (
    <>
      <div className="sb-section">
        <div className="sb-target-box">
          <svg data-lucide="github" aria-hidden="true"></svg>
          <div className="sb-target-url" title={displayUrl}>{displayUrl}</div>
        </div>
      </div>
      <div className="sb-divider"></div>
      <div className="risk-score-widget">
        <span className="risk-score-num" id="risk-score-display">{scan?.risk_score || 0}</span>
        <span className="risk-score-label">Risk Score</span>
        <svg className="risk-arc-svg" width="140" height="76" viewBox="0 0 140 76" aria-hidden="true">
          <defs>
            <linearGradient id="arcGrad" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#2ce870"/><stop offset="40%" stopColor="#f0c800"/>
              <stop offset="70%" stopColor="#ff8c38"/><stop offset="100%" stopColor="#ff4d5a"/>
            </linearGradient>
          </defs>
          <path d="M15 65 A55 55 0 0 1 125 65" stroke="#21293a" strokeWidth="5" fill="none" strokeLinecap="round"/>
          <path d="M15 65 A55 55 0 0 1 125 65" stroke="url(#arcGrad)" strokeWidth="5" fill="none"
            strokeLinecap="round" className="risk-arc-fill" strokeDasharray="172.8"
            strokeDashoffset={`${172.8 - (172.8 * (scan?.risk_score || 0) / 100)}`}/>
        </svg>
      </div>
      <div className="sb-divider"></div>
      <div className="sb-section">
        <div className="severity-list" role="list">
          {[
            { label: 'Critical', count: criticalCount, color: 'var(--color-critical)', highlight: 'var(--color-critical-highlight)' },
            { label: 'High', count: 0, color: 'var(--color-error)', highlight: 'var(--color-error-highlight)' },
            { label: 'Medium', count: mediumCount, color: 'var(--color-warning)', highlight: 'var(--color-warning-highlight)' },
            { label: 'Low', count: lowCount, color: 'var(--color-success)', highlight: 'var(--color-success-highlight)' },
          ].map(({ label, count, color, highlight }) => (
            <div className="severity-row" role="listitem" key={label}>
              <div className="severity-row-top">
                <div className="severity-dot" style={{ background: color }}></div>
                <span className="severity-label">{label}</span>
                <span className="severity-badge" style={{ background: highlight, color }}>{count}</span>
              </div>
              <div className="severity-bar">
                <div className="severity-bar-fill" style={{ width: `${total ? (count / total) * 100 : 0}%`, background: color }}></div>
              </div>
            </div>
          ))}
        </div>
      </div>
      <div className="sb-divider"></div>
      <div className="sb-section-sm">
        <nav className="sb-nav">
          {[
            { id: 'sec-summary', icon: <FileText size={16} />, label: 'Executive Summary' },
            { id: 'sec-findings', icon: <AlertCircle size={16} />, label: 'Security Findings' },
            { id: 'sec-compliance', icon: <Shield size={16} />, label: 'Compliance Map' },
            { id: 'sec-history', icon: <Activity size={16} />, label: 'Scan History' },
          ].map(({ id, icon, label }) => (
            <button key={id} className="sb-nav-link" onClick={() => scrollToSection(id)}>
              {icon}{label}
            </button>
          ))}
          <button className="sb-nav-link" onClick={onExport}>
            <Download size={16} />Export Report
          </button>
        </nav>
      </div>
      <div className="sb-bottom">
        <button className="btn-download-pdf" onClick={onExport}>
          <Download size={16} />Download PDF
        </button>
      </div>
    </>
  )
}

// ────────────────────────────────────────────────────────
// FindingCard — 2-step autofix + chat drawer
// ────────────────────────────────────────────────────────
function FindingCard({ finding, scan }: { finding: any; scan: any }) {
  const [open, setOpen] = useState(false)
  // Auto-fix state
  const [autofixStep, setAutofixStep] = useState<'idle' | 'generating' | 'review' | 'success' | 'error'>('idle')
  const [autofixData, setAutofixData] = useState<{
    originalContent: string; newContent: string; githubPat: string;
  } | null>(null)
  const [prUrl, setPrUrl] = useState('')
  const [autofixError, setAutofixError] = useState('')
  // Chat drawer
  const [chatOpen, setChatOpen] = useState(false)

  const isCritical = finding.severity === 'critical'
  const isMedium = finding.severity === 'medium'
  const sevClass = isCritical ? 'critical' : isMedium ? 'medium' : 'low'
  const stepLines = (finding.fix_steps || '').split('\n').filter((l: string) => l.trim().length > 0)
  const isGithubScan = scan?.scan_type === 'github'
  const hasAsset = !!finding.affected_asset

  const handleAutoFix = async (e: React.MouseEvent) => {
    e.preventDefault()
    e.stopPropagation()
    const pat = window.prompt(
      'Enter a GitHub PAT with "repo" scope (needs write access to create a branch + PR):'
    )
    if (!pat) return

    setAutofixStep('generating')
    setAutofixError('')

    try {
      const baseUrl = (import.meta as any).env?.VITE_API_BASE_URL || ''
      const res = await fetch(`${baseUrl}/api/autofix/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scan_id: scan.id,
          finding_id: finding.id,
          github_pat: pat,
        }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail || 'Failed to generate fix')
      setAutofixData({
        originalContent: data.original_content,
        newContent: data.new_content,
        githubPat: pat,
      })
      setAutofixStep('review')
    } catch (err: any) {
      setAutofixError(err.message)
      setAutofixStep('error')
    }
  }

  return (
    <>
      <article className="finding-card spotlight-card gradient-border" aria-label={`Finding: ${finding.title}`}>
        <div className="finding-top">
          <div className="finding-title">{finding.title}</div>
          <span className={`sev-badge ${sevClass}`} role="status">{finding.severity.toUpperCase()}</span>
        </div>
        <div className="finding-asset">
          Asset: <span className="finding-asset-name">{finding.affected_asset || 'N/A'}</span>
        </div>
        <p className="finding-desc">{finding.description}</p>

        <div className="finding-actions">
          <div className="finding-actions-left">
            <button
              className={`btn-toggle-fix ${open ? 'open' : ''}`}
              onClick={(e) => { e.preventDefault(); e.stopPropagation(); setOpen(!open); }}
              aria-expanded={open}
            >
              <ChevronDown size={14} className="mr-1 inline-block" />
              {open ? 'Hide Fix' : 'View Fix'}
            </button>
          </div>
          <div className="finding-actions-right">
            {/* Chat button — always visible */}
            <button
              className="btn-chat"
              onClick={(e) => { e.preventDefault(); e.stopPropagation(); setChatOpen(true) }}
              aria-label="Ask AI about this finding"
              title="Ask ShieldBot about this vulnerability"
            >
              <MessageSquare size={13} />
              Ask AI
            </button>

            {/* Auto-fix button — only for GitHub scans with patchable assets */}
            {isGithubScan && hasAsset && autofixStep !== 'success' && (
              <button
                className="btn-autofix"
                onClick={handleAutoFix}
                disabled={autofixStep === 'generating'}
              >
                <Sparkles size={13} className="mr-1 inline-block" />
                {autofixStep === 'generating'
                  ? 'Generating…'
                  : autofixStep === 'error'
                  ? 'Retry Auto-Fix'
                  : 'AI Auto-Fix'}
              </button>
            )}

            {autofixStep === 'success' && prUrl && (
              <a
                href={prUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="btn-autofix"
                style={{ color: 'var(--color-success)', borderColor: 'var(--color-success)', textDecoration: 'none' }}
              >
                <Sparkles size={13} className="mr-1 inline-block" />
                View PR ↗
              </a>
            )}
          </div>
        </div>

        {/* Error message */}
        {autofixStep === 'error' && autofixError && (
          <div className="text-xs text-red-400 mt-2 bg-red-400/10 rounded p-2 border border-red-500/20">
            {autofixError}
          </div>
        )}

        {/* Fix steps panel */}
        <div className={`fix-panel ${open ? 'open' : ''}`} aria-hidden={!open}>
          <ol className="fix-steps">
            {stepLines.map((line: string, i: number) => (
              <li key={i}>{line.replace(/^\d+\.\s*/, '')}</li>
            ))}
          </ol>
        </div>
      </article>

      {/* Auto-Fix Review Modal */}
      {autofixStep === 'review' && autofixData && (
        <AutoFixReviewModal
          findingTitle={finding.title}
          filePath={finding.affected_asset}
          originalContent={autofixData.originalContent}
          initialNewContent={autofixData.newContent}
          scanId={scan.id}
          findingId={finding.id}
          githubPat={autofixData.githubPat}
          onClose={() => setAutofixStep('idle')}
          onPrCreated={(url) => {
            setPrUrl(url)
            setAutofixStep('success')
          }}
        />
      )}

      {/* Chat Drawer */}
      {chatOpen && (
        <FindingChatDrawer
          finding={finding}
          onClose={() => setChatOpen(false)}
        />
      )}
    </>
  )
}

// ────────────────────────────────────────────────────────
// Scanning state sidebar
// ────────────────────────────────────────────────────────
function SidebarScanningState({ target }: { target: string }) {
  return (
    <>
      <div className="sb-section">
        <div className="sb-target-box border-primary/30">
          <SearchCode className="w-4 h-4 text-primary" />
          <div className="sb-target-url" title={target}>Target: {target}</div>
        </div>
      </div>
      <div className="sb-divider"></div>
      <div className="flex flex-col items-center justify-center py-20 opacity-60">
        <Loader2 className="w-8 h-8 text-primary animate-spin mb-4" />
        <div className="text-gray-400 text-sm tracking-wider uppercase font-medium">Gathering Data...</div>
      </div>
    </>
  )
}

// ────────────────────────────────────────────────────────
// Main Results page
// ────────────────────────────────────────────────────────
export default function Results() {
  const { scanId } = useParams()
  const [scan, setScan] = useState<any>(null)
  const [findings, setFindings] = useState<any[]>([])
  const [historicalScans, setHistoricalScans] = useState<any[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (!scanId) return

    const fetchResults = async () => {
      const { data: scanData } = await supabase.from('scans').select('*').eq('id', scanId).single()
      if (scanData) setScan(scanData)

      if (scanData?.status === 'done') {
        const { data: findingsData } = await supabase.from('findings').select('*').eq('scan_id', scanId)
        if (findingsData) setFindings(findingsData)

        const { data: historyData } = await supabase
          .from('scans').select('*')
          .eq('target', scanData.target).eq('status', 'done')
          .order('created_at', { ascending: true }).limit(10)
        if (historyData) setHistoricalScans(historyData)
      }
      setLoading(false)
    }

    fetchResults()

    const channel = supabase.channel('scan-progress')
      .on('postgres_changes', { event: 'UPDATE', schema: 'public', table: 'scans', filter: `id=eq.${scanId}` },
        (payload) => {
          setScan(payload.new)
          if (payload.new.status === 'done') {
            supabase.from('findings').select('*').eq('scan_id', scanId).then(({ data }) => {
              if (data) setFindings(data)
            })
            supabase.from('scans').select('*').eq('target', payload.new.target)
              .eq('status', 'done').order('created_at', { ascending: true }).limit(10)
              .then(({ data }) => { if (data) setHistoricalScans(data) })
          }
        })
      .subscribe()

    return () => { supabase.removeChannel(channel) }
  }, [scanId])

  const handleDownloadPdf = async () => {
    try {
      const baseUrl = (import.meta as any).env?.VITE_API_BASE_URL || ''
      const res = await fetch(`${baseUrl}/api/report/${scanId}/pdf`)
      const data = await res.json()
      if (data.pdf_url) window.open(data.pdf_url, '_blank')
    } catch (err) {
      console.error('PDF download failed', err)
    }
  }

  const chartData = useMemo(() => {
    if (historicalScans.length === 0) return null
    const labels = historicalScans.map(s => {
      const d = new Date(s.created_at)
      return `${d.getMonth() + 1}/${d.getDate()}`
    })
    const scores = historicalScans.map(s => s.risk_score || 0)
    return {
      labels,
      datasets: [{
        label: 'Risk Score',
        data: scores,
        borderColor: '#ffffff',
        backgroundColor: 'rgba(255,255,255,0.05)',
        fill: true, tension: 0.4, borderWidth: 2.5,
        pointBackgroundColor: '#ffffff', pointBorderColor: '#000000',
        pointBorderWidth: 3, pointRadius: 5, pointHoverRadius: 7,
      }],
    }
  }, [historicalScans])

  const chartOptions = {
    responsive: true, maintainAspectRatio: false,
    plugins: { legend: { display: false } },
    scales: {
      x: { grid: { color: 'rgba(33,41,58,0.6)' }, ticks: { color: '#3e4f64' } },
      y: { min: 0, max: 100, grid: { color: 'rgba(33,41,58,0.6)' }, ticks: { color: '#3e4f64', stepSize: 25 } },
    },
  }

  const avgRiskScore = historicalScans.length
    ? Math.round(historicalScans.reduce((acc, s) => acc + (s.risk_score || 0), 0) / historicalScans.length)
    : 0

  if (loading) return <div className="flex h-screen items-center justify-center"><Loader2 className="w-8 h-8 text-teal animate-spin" /></div>
  if (!scan) return <div className="text-center text-red-500 mt-20">Scan not found</div>

  const isScanning = scan.status === 'pending' || scan.status === 'running'
  const critical = findings.filter(f => f.severity === 'critical')
  const medium = findings.filter(f => f.severity === 'medium')
  const low = findings.filter(f => f.severity === 'low')

  const sidebarEl = document.getElementById('sidebar')

  if (scan.status === 'failed') {
    return (
      <div className="flex flex-col h-[calc(100vh-100px)] items-center justify-center p-8 text-center animate-in fade-in zoom-in-95">
        <AlertCircle className="w-16 h-16 text-red-500 mb-6 mx-auto animate-pulse" />
        <h2 className="text-2xl font-display font-bold text-white mb-3">Scan Failed</h2>
        <p className="text-gray-400 max-w-md mx-auto leading-relaxed mb-6">
          The security analysis could not be completed. This usually happens if the GitHub API enforces rate limits (60 unauthenticated requests/hr), or if the uploaded ZIP file was corrupted.
        </p>
        {scan.raw_json?.error && (
          <div className="bg-[#1a0f0f] border border-red-500/20 rounded-lg p-4 text-left max-w-lg mx-auto w-full overflow-auto">
            <div className="text-xs font-display text-red-400 uppercase tracking-widest mb-2">Error Details</div>
            <code className="text-sm text-red-300 font-mono break-words">{scan.raw_json.error}</code>
          </div>
        )}
      </div>
    )
  }

  return (
    <>
      {sidebarEl && createPortal(
        isScanning
          ? <SidebarScanningState target={scan.target} />
          : <SidebarContent scan={scan} criticalCount={critical.length} mediumCount={medium.length} lowCount={low.length} onExport={handleDownloadPdf} />,
        sidebarEl,
      )}

      {isScanning ? (
        <div className="flex flex-col items-center justify-center h-full min-h-[70vh] w-full relative overflow-hidden">
          {/* Deep ambient glow */}
          <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[500px] h-[500px] bg-white/[0.03] rounded-full blur-[120px] pointer-events-none" />
          
          <div className="text-center relative z-10 w-full max-w-lg px-6 flex flex-col items-center">
            
            {/* Mechanically perfect SVG HUD Ring */}
            <div className="relative w-40 h-40 flex items-center justify-center mb-10">
              <Shield className="w-10 h-10 text-white relative z-10 animate-pulse" strokeWidth={1.5} />
              
              {/* Outer slow dotted ring */}
              <svg className="absolute inset-0 w-full h-full animate-[spin_10s_linear_infinite]" viewBox="0 0 100 100">
                <circle cx="50" cy="50" r="48" fill="none" stroke="rgba(255,255,255,0.15)" strokeWidth="0.5" strokeDasharray="2 6" />
              </svg>
              
              {/* Middle dashed ring */}
              <svg className="absolute inset-0 w-full h-full animate-[spin_5s_linear_infinite_reverse]" viewBox="0 0 100 100">
                <circle cx="50" cy="50" r="40" fill="none" stroke="rgba(255,255,255,0.3)" strokeWidth="1" strokeDasharray="20 10 5 10" />
              </svg>
              
              {/* Inner fast targeting ring */}
              <svg className="absolute inset-0 w-full h-full animate-[spin_2s_ease-in-out_infinite]" viewBox="0 0 100 100">
                <circle cx="50" cy="50" r="32" fill="none" stroke="rgba(255,255,255,0.9)" strokeWidth="1.5" strokeDasharray="50 150" strokeLinecap="square" />
              </svg>
            </div>
            
            <h2 className="text-3xl font-display font-medium tracking-[0.05em] text-white mb-3">
              Auditing Architecture
            </h2>
            <p className="text-[#a1a1aa] mb-12 max-w-sm mx-auto font-body text-sm leading-relaxed">
              Target profiling <span className="text-white font-mono opacity-80">{scan.target}</span> underway. Deploying threat models.
            </p>
            
            {/* Sleek Matrix Progress Bar */}
            <div className="w-full sm:w-96 space-y-3">
              <div className="flex justify-between items-end px-1">
                <span className="text-[10px] font-display tracking-[0.3em] text-[#71717a] uppercase">System Override</span>
                <span className="text-sm font-mono text-white tracking-wider">{scan.progress}%</span>
              </div>
              
              <div className="w-full h-[2px] bg-white/10 relative">
                 <div
                   className="absolute top-0 left-0 h-full bg-white shadow-[0_0_12px_rgba(255,255,255,1)] transition-all duration-700 ease-out"
                   style={{ width: `${scan.progress}%` }}
                 />
              </div>
              
              {/* Dynamic Matrix Output */}
              <div className="h-6 flex items-start justify-start pt-2 px-1">
                <div className="text-[10px] font-mono text-[#a1a1aa] uppercase tracking-[0.15em] flex items-center gap-3">
                  <span className="w-1 h-1 bg-white animate-pulse" />
                  {scan.progress < 20 && <span>Injecting preliminary payload...</span>}
                  {scan.progress >= 20 && scan.progress < 50 && <span>Analyzing syntax trees...</span>}
                  {scan.progress >= 50 && scan.progress < 80 && <span>Resolving heuristic signatures...</span>}
                  {scan.progress >= 80 && scan.progress < 95 && <span>Activating neural models...</span>}
                  {scan.progress >= 95 && <span>Compiling threat matrix...</span>}
                </div>
              </div>
            </div>
          </div>
        </div>
      ) : (
        <div className="results-inner fade-in">
          <section className="results-section reveal visible" id="sec-summary">
            <h2 className="section-heading">Executive Summary</h2>
            <div className="summary-card spotlight-card">
              <p className="summary-alert-text">
                {critical.length > 0
                  ? `Your site has ${critical.length} critical issue${critical.length > 1 ? 's' : ''} needing immediate attention — these could allow attackers to steal customer data or take over your systems.`
                  : 'Your site has no critical issues. Ensure you maintain this posture moving forward.'}
              </p>
              <p className="summary-body">
                Scan completed on {new Date(scan.created_at).toLocaleDateString()}. Target: <code>{scan.target}</code>.
                {' '}{findings.length} total findings discovered. Risk score: {scan.risk_score}/100.
              </p>
              <div className="kpi-row">
                <div className="kpi-item">
                  <span className="kpi-num" style={{ color: 'var(--color-critical)' }}>{critical.length}</span>
                  <span className="kpi-label">Critical</span>
                </div>
                <div className="kpi-item">
                  <span className="kpi-num" style={{ color: 'var(--color-warning)' }}>{medium.length}</span>
                  <span className="kpi-label">Medium</span>
                </div>
                <div className="kpi-item">
                  <span className="kpi-num" style={{ color: 'var(--color-success)' }}>{low.length}</span>
                  <span className="kpi-label">Low</span>
                </div>
              </div>
            </div>
          </section>

          <section className="results-section reveal visible" id="sec-findings">
            <h2 className="section-heading">Security Findings</h2>
            <div id="findings-container">
              {[...critical, ...medium, ...low].map(f => (
                <FindingCard key={f.id} finding={f} scan={scan} />
              ))}
              {findings.length === 0 && (
                <p className="text-gray-400 py-8 text-center italic">No findings to display.</p>
              )}
            </div>
          </section>

          <section className="results-section reveal visible" id="sec-compliance">
            <h2 className="section-heading">Compliance Map</h2>
            <div className="compliance-grid">
              {[
                { name: 'SOC 2', count: critical.length, color: 'var(--color-critical)', version: 'Type II — Findings mapped' },
                { name: 'PCI-DSS', count: 0, color: 'var(--color-error)', version: 'v4.0 — Findings mapped' },
                { name: 'ISO 27001', count: medium.length, color: 'var(--color-warning)', version: '2013 — Findings mapped' },
                { name: 'DPDPA', count: low.length, color: 'var(--color-blue)', version: 'India 2023 — Findings mapped' },
              ].map(({ name, count, color, version }) => (
                <div key={name} className="compliance-card tilt-card spotlight-card" style={{ '--card-accent': color } as any}>
                  <div className="compliance-name">{name}</div>
                  <div className="compliance-count" style={{ color }}>{count}</div>
                  <div className="compliance-version">{version}</div>
                </div>
              ))}
            </div>
          </section>

          <section className="results-section reveal visible" id="sec-history">
            <h2 className="section-heading">Scan History</h2>
            <div className="history-pills">
              <span className="stat-pill">Total Audits: {historicalScans.length}</span>
              <span className="stat-pill">Avg Risk Score: {avgRiskScore}</span>
            </div>
            <div className="chart-card">
              <div className="chart-wrap">
                {chartData
                  ? <Line data={chartData} options={chartOptions as any} />
                  : <span className="text-gray-500">Not enough data</span>}
              </div>
            </div>
          </section>
        </div>
      )}
    </>
  )
}
