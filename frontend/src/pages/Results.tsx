import { useEffect, useState, useMemo } from 'react'
import { useParams } from 'react-router-dom'
import { createPortal } from 'react-dom'
import { supabase } from '../lib/supabase'
import { Loader2, Download, SearchCode, Sparkles, AlertCircle, FileText, Activity, Shield, ChevronDown } from 'lucide-react'
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  Filler,
} from 'chart.js'
import { Line } from 'react-chartjs-2'

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  Filler
)

function SidebarContent({ scan, criticalCount, mediumCount, lowCount, onExport }: any) {
  const displayUrl = scan?.target || 'loading...';
  const total = criticalCount + mediumCount + lowCount;
  
  const scrollToSection = (id: string) => {
    const el = document.getElementById(id);
    if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
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
                strokeLinecap="round" className="risk-arc-fill" strokeDasharray="172.8" strokeDashoffset={`${172.8 - (172.8 * (scan?.risk_score || 0) / 100)}`}/>
        </svg>
      </div>
      <div className="sb-divider"></div>
      <div className="sb-section">
        <div className="severity-list" role="list">
          <div className="severity-row" role="listitem">
            <div className="severity-row-top">
              <div className="severity-dot" style={{ background: 'var(--color-critical)' }}></div>
              <span className="severity-label">Critical</span>
              <span className="severity-badge" style={{ background: 'var(--color-critical-highlight)', color: 'var(--color-critical)' }}>{criticalCount}</span>
            </div>
            <div className="severity-bar"><div className="severity-bar-fill" style={{ width: `${total ? (criticalCount/total)*100 : 0}%`, background: 'var(--color-critical)' }}></div></div>
          </div>
          <div className="severity-row" role="listitem">
            <div className="severity-row-top">
              <div className="severity-dot" style={{ background: 'var(--color-error)' }}></div>
              <span className="severity-label">High</span>
              <span className="severity-badge" style={{ background: 'var(--color-error-highlight)', color: 'var(--color-error)' }}>0</span>
            </div>
            <div className="severity-bar"><div className="severity-bar-fill" style={{ width: '0%', background: 'var(--color-error)' }}></div></div>
          </div>
          <div className="severity-row" role="listitem">
            <div className="severity-row-top">
              <div className="severity-dot" style={{ background: 'var(--color-warning)' }}></div>
              <span className="severity-label">Medium</span>
              <span className="severity-badge" style={{ background: 'var(--color-warning-highlight)', color: 'var(--color-warning)' }}>{mediumCount}</span>
            </div>
            <div className="severity-bar"><div className="severity-bar-fill" style={{ width: `${total ? (mediumCount/total)*100 : 0}%`, background: 'var(--color-warning)' }}></div></div>
          </div>
          <div className="severity-row" role="listitem">
            <div className="severity-row-top">
              <div className="severity-dot" style={{ background: 'var(--color-success)' }}></div>
              <span className="severity-label">Low</span>
              <span className="severity-badge" style={{ background: 'var(--color-success-highlight)', color: 'var(--color-success)' }}>{lowCount}</span>
            </div>
            <div className="severity-bar"><div className="severity-bar-fill" style={{ width: `${total ? (lowCount/total)*100 : 0}%`, background: 'var(--color-success)' }}></div></div>
          </div>
        </div>
      </div>
      <div className="sb-divider"></div>
      <div className="sb-section-sm">
        <nav className="sb-nav">
          <button className="sb-nav-link" onClick={() => scrollToSection('sec-summary')}>
            <FileText size={16} />Executive Summary
          </button>
          <button className="sb-nav-link" onClick={() => scrollToSection('sec-findings')}>
            <AlertCircle size={16} />Security Findings
          </button>
          <button className="sb-nav-link" onClick={() => scrollToSection('sec-compliance')}>
            <Shield size={16} />Compliance Map
          </button>
          <button className="sb-nav-link" onClick={() => scrollToSection('sec-history')}>
            <Activity size={16} />Scan History
          </button>
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

function FindingCard({ finding, scan }: { finding: any, scan: any }) {
  const [open, setOpen] = useState(false)
  const [autofixStatus, setAutofixStatus] = useState<'idle' | 'loading' | 'success' | 'error'>('idle')
  const [prUrl, setPrUrl] = useState('')
  const [autofixError, setAutofixError] = useState('')
  const isCritical = finding.severity === 'critical';
  const isMedium = finding.severity === 'medium';
  
  const sevClass = isCritical ? 'critical' : isMedium ? 'medium' : 'low';
  
  const rawSteps = finding.fix_steps || ""
  const stepLines = rawSteps.split('\n').filter((l: string) => l.trim().length > 0)

  const handleAutoFix = async (e: React.MouseEvent) => {
    e.stopPropagation()
    const pat = window.prompt('Enter a GitHub PAT with "repo" scope (needs write access to create a branch + open a Pull Request on your behalf):')
    if (!pat) return

    setAutofixStatus('loading')
    setAutofixError('')

    try {
      const baseUrl = import.meta.env.VITE_API_BASE_URL || ''
      const res = await fetch(`${baseUrl}/api/autofix`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scan_id: scan.id,
          finding_id: finding.id,
          github_pat: pat,
        })
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail || 'Auto-fix failed')
      setPrUrl(data.pr_url)
      setAutofixStatus('success')
    } catch (err: any) {
      setAutofixError(err.message)
      setAutofixStatus('error')
    }
  }

  return (
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
        <button className={`btn-toggle-fix ${open ? 'open' : ''}`} onClick={() => setOpen(!open)} aria-expanded={open}>
          <ChevronDown size={14} className="mr-1 inline-block" />
          {open ? 'Hide Fix' : 'View Fix'}
        </button>
        {scan?.scan_type === 'github' && finding.affected_asset && autofixStatus !== 'success' && (
          <button
            className="btn-autofix"
            onClick={handleAutoFix}
            disabled={autofixStatus === 'loading'}
          >
            <Sparkles size={14} className="mr-1 inline-block" />
            {autofixStatus === 'loading' ? 'Generating PR…' : autofixStatus === 'error' ? 'Retry Auto-Fix' : 'AI Auto-Fix'}
          </button>
        )}
        {autofixStatus === 'success' && prUrl && (
          <a
            href={prUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="btn-autofix"
            style={{ color: 'var(--color-success)', borderColor: 'var(--color-success)', textDecoration: 'none' }}
          >
            <Sparkles size={14} className="mr-1 inline-block" />
            View PR ↗
          </a>
        )}
      </div>
      {autofixStatus === 'error' && autofixError && (
        <div className="text-xs text-red-400 mt-2 bg-red-400/10 rounded p-2 border border-red-500/20">
          {autofixError}
        </div>
      )}
      <div className={`fix-panel ${open ? 'open' : ''}`} aria-hidden={!open}>
        <ol className="fix-steps">
          {stepLines.map((line: string, i: number) => (
            <li key={i}>{line.replace(/^\d+\.\s*/, '')}</li>
          ))}
        </ol>
      </div>
    </article>
  )
}

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
          .from('scans')
          .select('*')
          .eq('target', scanData.target)
          .eq('status', 'done')
          .order('created_at', { ascending: true })
          .limit(10)
          
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
          // Re-fetch findings
          supabase.from('findings').select('*').eq('scan_id', scanId).then(({ data }) => {
            if (data) setFindings(data)
          })
          // Re-fetch history
          supabase.from('scans').select('*').eq('target', payload.new.target).eq('status', 'done').order('created_at', { ascending: true }).limit(10).then(({ data }) => {
            if (data) setHistoricalScans(data)
          })
        }
      })
      .subscribe()

    return () => { supabase.removeChannel(channel) }
  }, [scanId])

  const handleDownloadPdf = async () => {
    try {
      const baseUrl = import.meta.env.VITE_API_BASE_URL || ''
      const res = await fetch(`${baseUrl}/api/report/${scanId}/pdf`)
      const data = await res.json()
      if (data.pdf_url) {
        window.open(data.pdf_url, '_blank')
      }
    } catch (err) {
      console.error("PDF download failed", err)
    }
  }

  const chartData = useMemo(() => {
    if (historicalScans.length === 0) return null;
    const labels = historicalScans.map(s => {
      const d = new Date(s.created_at);
      return `${d.getMonth()+1}/${d.getDate()}`;
    });
    const scores = historicalScans.map(s => s.risk_score || 0);
    
    return {
      labels,
      datasets: [{
        label: 'Risk Score',
        data: scores,
        borderColor: '#ffffff',
        backgroundColor: 'rgba(255,255,255,0.05)',
        fill: true,
        tension: 0.4,
        borderWidth: 2.5,
        pointBackgroundColor: '#ffffff',
        pointBorderColor: '#000000',
        pointBorderWidth: 3,
        pointRadius: 5,
        pointHoverRadius: 7,
      }]
    };
  }, [historicalScans]);

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false }
    },
    scales: {
      x: {
        grid: { color: 'rgba(33,41,58,0.6)', drawBorder: false },
        ticks: { color: '#3e4f64' }
      },
      y: {
        min: 0,
        max: 100,
        grid: { color: 'rgba(33,41,58,0.6)', drawBorder: false },
        ticks: { color: '#3e4f64', stepSize: 25 }
      }
    }
  };

  const avgRiskScore = historicalScans.length ? Math.round(historicalScans.reduce((acc, current) => acc + (current.risk_score || 0), 0) / historicalScans.length) : 0;

  if (loading) return <div className="flex h-screen items-center justify-center"><Loader2 className="w-8 h-8 text-teal animate-spin" /></div>
  if (!scan) return <div className="text-center text-red-500 mt-20">Scan not found</div>

  const isScanning = scan.status === 'pending' || scan.status === 'running'
  const critical = findings.filter(f => f.severity === 'critical')
  const medium = findings.filter(f => f.severity === 'medium')
  const low = findings.filter(f => f.severity === 'low')
  
  const sidebarEl = document.getElementById('sidebar');

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
         isScanning ? <SidebarScanningState target={scan.target} /> : <SidebarContent scan={scan} criticalCount={critical.length} mediumCount={medium.length} lowCount={low.length} onExport={handleDownloadPdf} />, 
         sidebarEl
      )}

      {isScanning ? (
        <div className="flex flex-col items-center justify-center min-h-[calc(100vh-100px)] w-full">
           <div className="text-center">
             <div className="relative w-24 h-24 mx-auto flex items-center justify-center mb-8 bg-[#0d1117] rounded-full border border-primary/50 shadow-[0_0_30px_rgba(0,212,222,0.2)] animate-pulse">
                 <SearchCode className="w-10 h-10 text-primary" />
             </div>
             
             <h2 className="text-2xl font-semibold mb-2">Audit in Progress</h2>
             <p className="text-gray-400 mb-8 max-w-sm mx-auto">
                Analyzing {scan.target} across 14 security dimensions. Please wait, this takes about a minute.
             </p>
             
             <div className="w-64 mx-auto space-y-2">
               <div className="flex justify-between text-sm font-medium">
                   <span className="text-primary">Scan Progress</span>
                   <span className="text-white">{scan.progress}%</span>
               </div>
               <div className="w-full h-2 bg-gray-900 rounded-full overflow-hidden border border-gray-800">
                   <div 
                       className="h-full bg-gradient-to-r from-primary to-blue-500 rounded-full transition-all duration-500 ease-out relative"
                       style={{ width: `${scan.progress}%` }}
                   />
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
                {critical.length > 0 ? `Your site has ${critical.length} critical issues needing immediate attention — these could allow attackers to steal customer data or take over your systems.` : "Your site has no critical issues. Ensure you maintain this posture moving forward."}
              </p>
              <p className="summary-body">
                Scan completed on {new Date(scan.created_at).toLocaleDateString()}. Target: <code>{scan.target}</code>.
                {findings.length} total findings discovered. Risk score: {scan.risk_score}/100.
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
              <div className="compliance-card tilt-card spotlight-card" style={{ '--card-accent': 'var(--color-critical)' } as any}>
                <div className="compliance-name">SOC 2</div>
                <div className="compliance-count" style={{ color: 'var(--color-critical)' }}>{ critical.length }</div>
                <div className="compliance-version">Type II — Findings mapped</div>
              </div>
              <div className="compliance-card tilt-card spotlight-card" style={{ '--card-accent': 'var(--color-error)' } as any}>
                <div className="compliance-name">PCI-DSS</div>
                <div className="compliance-count" style={{ color: 'var(--color-error)' }}>0</div>
                <div className="compliance-version">v4.0 — Findings mapped</div>
              </div>
              <div className="compliance-card tilt-card spotlight-card" style={{ '--card-accent': 'var(--color-warning)' } as any}>
                <div className="compliance-name">ISO 27001</div>
                <div className="compliance-count" style={{ color: 'var(--color-warning)' }}>{ medium.length }</div>
                <div className="compliance-version">2013 — Findings mapped</div>
              </div>
              <div className="compliance-card tilt-card spotlight-card" style={{ '--card-accent': 'var(--color-blue)' } as any}>
                <div className="compliance-name">DPDPA</div>
                <div className="compliance-count" style={{ color: 'var(--color-blue)' }}>{ low.length }</div>
                <div className="compliance-version">India 2023 — Findings mapped</div>
              </div>
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
                {chartData ? <Line data={chartData} options={chartOptions as any} /> : <span className="text-gray-500">Not enough data</span>}
              </div>
            </div>
          </section>
        </div>
      )}
    </>
  )
}
