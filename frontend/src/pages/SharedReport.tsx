import { useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import { CheckCircle, AlertCircle, AlertTriangle, FileText, Download } from 'lucide-react'
import { cn } from '../lib/utils'

export default function SharedReport() {
  const { uuid } = useParams()
  const [scan, setScan] = useState<any>(null)
  const [findings, setFindings] = useState<any[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (!uuid) return

    const fetchReport = async () => {
      try {
        const baseUrl = import.meta.env.VITE_API_BASE_URL || ''
        const res = await fetch(`${baseUrl}/api/report/${uuid}`)
        const data = await res.json()
        if (data.scan) {
            setScan(data.scan)
            setFindings(data.findings || [])
        }
      } catch (err) {
        console.error(err)
      } finally {
        setLoading(false)
      }
    }
    fetchReport()
  }, [uuid])

  const handleDownloadPdf = async () => {
      try {
        const res = await fetch(`${import.meta.env.VITE_API_BASE_URL}/api/report/${uuid}/pdf`)
        const data = await res.json()
        if (data.pdf_url) {
            window.open(data.pdf_url, '_blank')
        }
      } catch (err) { }
  }

  if (loading) return <div className="text-center mt-20 text-teal">Loading shared report...</div>
  if (!scan) return <div className="text-center text-red-500 mt-20">Report not found</div>

  const critical = findings.filter(f => f.severity === 'critical')
  const medium = findings.filter(f => f.severity === 'medium')
  const low = findings.filter(f => f.severity === 'low')

  return (
    <div className="w-full space-y-8 animate-in fade-in duration-700">
      <div className="bg-gold/10 border border-gold/20 rounded-lg p-4 mb-4 flex items-center justify-between">
          <span className="text-gold text-sm font-medium">You are viewing a shared public report.</span>
          <button className="flex items-center gap-2 bg-card hover:bg-card/80 border border-teal text-teal px-4 py-2 rounded-lg text-sm transition-colors shadow-lg" onClick={() => window.location.href="/"}>
            Start Your Own Scan
          </button>
      </div>

      <div className="flex flex-col md:flex-row justify-between items-start md:items-end gap-4 pb-6 border-b border-card">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Security Audit Report</h1>
          <p className="text-gray-400 mt-1 flex items-center gap-2">
            <span className="bg-card px-2 py-1 rounded text-sm font-mono border border-gray-800">{scan.target}</span>
            <span className="text-sm">via {scan.scan_type.toUpperCase()}</span>
          </p>
        </div>
        <button onClick={handleDownloadPdf} className="flex items-center gap-2 px-4 py-2 bg-gold/10 hover:bg-gold/20 border border-gold/30 text-gold rounded-lg text-sm font-medium transition-colors">
            <Download className="w-4 h-4" /> Download PDF
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="col-span-1 bg-card/40 border border-gray-800 rounded-2xl p-6 flex flex-col items-center justify-center shadow-lg relative overflow-hidden">
              <div className="absolute top-0 inset-x-0 h-1 bg-gradient-to-r from-red-500 via-yellow-500 to-green-500 opacity-20" />
              <h3 className="text-gray-400 text-sm uppercase tracking-widest font-semibold mb-6">Business Risk Score</h3>
              
              <div className="relative w-48 h-48 flex items-center justify-center">
                  <svg className="w-full h-full transform -rotate-90" viewBox="0 0 36 36">
                      <path className="text-gray-800" strokeWidth="3" stroke="currentColor" fill="none" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
                      <path 
                          className={cn("transition-all duration-1000 ease-out", scan.risk_score >= 70 ? "text-green-500" : scan.risk_score >= 40 ? "text-yellow-500" : "text-red-500")}
                          strokeWidth="3" 
                          strokeDasharray={`${scan.risk_score}, 100`}
                          stroke="currentColor" fill="none" strokeLinecap="round"
                          d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" 
                      />
                  </svg>
                  <div className="absolute inset-0 flex flex-col items-center justify-center">
                      <span className="text-5xl font-bold tracking-tighter">{scan.risk_score}</span>
                      <span className="text-sm text-gray-400 mt-1">/ 100</span>
                  </div>
              </div>
          </div>
          
          <div className="col-span-1 md:col-span-2 bg-gradient-to-br from-card to-card/50 border border-gray-800 rounded-2xl p-8 shadow-lg flex flex-col">
              <div className="flex items-center gap-2 mb-4 text-gold">
                  <FileText className="w-5 h-5" />
                  <h3 className="font-semibold tracking-wide">Executive Summary</h3>
              </div>
              <div className="flex-grow">
                  <p className="text-lg leading-relaxed text-gray-300 font-light">
                      {scan.ai_report?.executive_summary || "No summary available."}
                  </p>
              </div>
          </div>
      </div>

      {/* Findings Columns */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="space-y-4">
              <div className="flex items-center gap-2 border-b-2 border-red-500/50 pb-2">
                  <AlertCircle className="w-5 h-5 text-red-500" />
                  <h3 className="font-semibold text-lg">Critical ({critical.length})</h3>
              </div>
              {critical.map(f => <FindingCard key={f.id} finding={f} />)}
          </div>
          <div className="space-y-4">
              <div className="flex items-center gap-2 border-b-2 border-yellow-500/50 pb-2">
                  <AlertTriangle className="w-5 h-5 text-yellow-500" />
                  <h3 className="font-semibold text-lg">Medium ({medium.length})</h3>
              </div>
              {medium.map(f => <FindingCard key={f.id} finding={f} />)}
          </div>
          <div className="space-y-4">
              <div className="flex items-center gap-2 border-b-2 border-green-500/50 pb-2">
                  <CheckCircle className="w-5 h-5 text-green-500" />
                  <h3 className="font-semibold text-lg">Low ({low.length})</h3>
              </div>
              {low.map(f => <FindingCard key={f.id} finding={f} />)}
          </div>
      </div>
    </div>
  )
}

function FindingCard({ finding }: { finding: any }) {
    const [open, setOpen] = useState(false)
    const colorClass = finding.severity === 'critical' ? 'border-red-500/30' : finding.severity === 'medium' ? 'border-yellow-500/30' : 'border-green-500/30'
    const bgClass = finding.severity === 'critical' ? 'hover:bg-red-500/5' : finding.severity === 'medium' ? 'hover:bg-yellow-500/5' : 'hover:bg-green-500/5'
    
    return (
        <div className={cn("bg-card border rounded-xl overflow-hidden transition-all duration-200", colorClass, bgClass)}>
            <div className="p-4 cursor-pointer flex justify-between items-start gap-4" onClick={() => setOpen(!open)}>
                <div>
                    <h4 className="font-medium text-sm text-gray-200 leading-tight">{finding.title}</h4>
                </div>
            </div>
            {open && (
                <div className="px-4 pb-4 pt-2 border-t border-gray-800 bg-background/30 text-sm space-y-4">
                    <div>
                        <strong className="text-gray-400 text-xs uppercase tracking-wider block mb-1">Impact</strong>
                        <p className="text-gray-300 leading-relaxed">{finding.description}</p>
                    </div>
                </div>
            )}
        </div>
    )
}
