import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { supabase } from '../lib/supabase'
import { 
  Code, Package, Globe, ShieldCheck, Server, Key, Lock, AlertTriangle, Cpu, Zap, GitBranch, UploadCloud
} from 'lucide-react'

export default function Home() {
  const [activeTab, setActiveTab] = useState<'url' | 'github' | 'zip'>('github')
  const [target, setTarget] = useState('')
  const [pat, setPat] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const navigate = useNavigate()

  useEffect(() => {
    let active = true
    // Typewriter effect logic
    const heading = document.getElementById('hero-heading')
    if (heading) {
      const text = 'One URL. One Click.<br>Total Visibility.'
      let i = 0
      heading.innerHTML = ''
      const cursor = document.createElement('span')
      cursor.className = 'typewriter-cursor'

      function tick() {
        if (!active || !heading) return
        if (i < text.length) {
          if (text.substring(i, i + 4) === '<br>') {
            heading.appendChild(document.createElement('br'))
            i += 4
          } else {
            heading.appendChild(document.createTextNode(text[i]))
            i++
          }
          if (cursor.parentNode) cursor.remove()
          heading.appendChild(cursor)
          setTimeout(tick, 45)
        } else {
          setTimeout(() => { if (active) cursor.remove() }, 2000)
        }
      }
      setTimeout(tick, 300)
    }
    return () => {
      active = false
    }
  }, [])

  const handleScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault()
    
    // Auth check
    const { data: { session } } = await supabase.auth.getSession()
    if (!session) {
      navigate('/auth')
      return
    }

    let finalTarget = target.trim()
    // Default placeholders
    if (!finalTarget) {
      finalTarget = activeTab === 'github' ? 'https://github.com/nightfury12901/VigilX' : 'https://yourdomain.com'
    }

    setError('')
    setLoading(true)

    try {
      const endpoint = `/api/scan/${activeTab}`
      const payload: any = {}

      if (activeTab === 'url') payload.url = finalTarget
      if (activeTab === 'github') {
        payload.repo_url = finalTarget
        if (pat) payload.github_pat = pat
      }
      if (activeTab === 'zip') payload.storage_path = `zip-uploads/${finalTarget}`

      const baseUrl = import.meta.env.VITE_API_BASE_URL || ''
      const res = await fetch(`${baseUrl}${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      })
      
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail || 'Scan failed to start')
      
      navigate(`/results/${data.scan_id}`)
    } catch (err: any) {
      setError(err.message)
      setLoading(false)
    }
  }

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    
    if (file.size > 50 * 1024 * 1024) {
      setError('File size must be under 50MB')
      return
    }
    
    setLoading(true)
    setError('Uploading ZIP... please wait.')
    
    const fileExt = file.name.split('.').pop()
    const fileName = `${Math.random().toString(36).substring(2)}_${Date.now()}.${fileExt}`
    
    const { data, error: uploadError } = await supabase.storage
      .from('zip-uploads')
      .upload(fileName, file)
    
    if (uploadError) {
      setError(`Upload failed: ${uploadError.message}`)
      setLoading(false)
      return
    }
    
    setTarget(data.path)
    setError('')
    setLoading(false)
  }

  return (
    <div className="landing-container fade-in mt-10">
      <p className="landing-eyebrow">// Security Audit Platform</p>
      <h1 className="landing-h1" id="hero-heading" aria-label="One URL. One Click. Total Visibility."></h1>
      <p className="landing-sub">
        ShieldScan runs 9 concurrent security modules against your GitHub
        repository or live URL and delivers a plain-English risk report
        in under 60 seconds.
      </p>

      {error && (
        <div className="text-red-400 mb-4 text-sm bg-red-400/10 p-3 rounded-lg border border-red-500/20 max-w-lg mx-auto">
          {error}
        </div>
      )}

      <div className="scan-card gradient-border relative">
        <div className="scan-card-line"></div>
        <div className="tab-row" role="tablist">
          <button 
            type="button"
            className={`tab-btn ${activeTab === 'github' ? 'active' : ''}`}
            role="tab" 
            aria-selected={activeTab === 'github'} 
            onClick={() => { setActiveTab('github'); setTarget(''); setError(''); }}
          >
            <GitBranch size={16} /> GitHub Repository
          </button>
          <button 
            type="button"
            className={`tab-btn ${activeTab === 'url' ? 'active' : ''}`}
            role="tab" 
            aria-selected={activeTab === 'url'} 
            onClick={() => { setActiveTab('url'); setTarget(''); setError(''); }}
          >
            <Globe size={16} /> Live URL
          </button>
          <button 
            type="button"
            className={`tab-btn ${activeTab === 'zip' ? 'active' : ''}`}
            role="tab" 
            aria-selected={activeTab === 'zip'} 
            onClick={() => { setActiveTab('zip'); setTarget(''); setError(''); }}
          >
            <Package size={16} /> ZIP File
          </button>
        </div>

        <div className="input-wrap">
          {activeTab === 'zip' ? (
             <div className="flex flex-col items-center justify-center p-6 border border-dashed border-gray-700/50 rounded-lg w-full bg-[#111] hover:bg-[#151515] transition cursor-pointer relative">
               <input 
                 type="file" 
                 accept=".zip" 
                 className="absolute inset-0 opacity-0 cursor-pointer" 
                 onChange={handleFileUpload}
               />
               <UploadCloud className="w-8 h-8 text-gray-500 mb-2" />
               <span className="text-sm text-gray-400">
                 {target ? target : 'Click or drop .zip file (Max 50MB)'}
               </span>
             </div>
          ) : (
            <>
              <input 
                type="text" 
                id="scan-url-input" 
                className="scan-input"
                placeholder={activeTab === 'github' ? 'https://github.com/username/repo' : 'https://yourdomain.com'}
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter') handleScan(); }}
                autoComplete="off" 
                spellCheck="false"
                aria-label="Enter target to scan"
              />
              <span className="input-hint">Enter ↵</span>
            </>
          )}
        </div>

        {activeTab === 'github' && (
          <div className="input-wrap animate-in fade-in slide-in-from-top-2">
            <input 
               type="password" 
               placeholder="GitHub PAT (Optional, for private repos)"
               value={pat}
               onChange={e => setPat(e.target.value)}
               className="scan-input"
               style={{ paddingRight: '18px' }}
            />
          </div>
        )}

        <button 
          className="btn-start-scan disabled:opacity-50 disabled:cursor-not-allowed" 
          onClick={() => handleScan()}
          disabled={loading}
        >
          <Zap size={16} aria-hidden="true" />
          {loading ? 'Initializing Scan...' : 'Start Scan'}
        </button>
      </div>

      <div className="module-pills" role="list">
        <div className="module-pill" role="listitem"><Code size={14} />Static Analysis</div>
        <div className="module-pill" role="listitem"><Package size={14} />Dependency Audit</div>
        <div className="module-pill" role="listitem"><Globe size={14} />External Audit</div>
        <div className="module-pill" role="listitem"><ShieldCheck size={14} />SSL/TLS Check</div>
        <div className="module-pill" role="listitem"><Server size={14} />DNS Scan</div>
        <div className="module-pill" role="listitem"><Key size={14} />Secret Detection</div>
        <div className="module-pill" role="listitem"><Lock size={14} />Auth Headers</div>
        <div className="module-pill" role="listitem"><AlertTriangle size={14} />CVE Database</div>
        <div className="module-pill" role="listitem"><Cpu size={14} />AI Auto-Fix</div>
      </div>
    </div>
  )
}
