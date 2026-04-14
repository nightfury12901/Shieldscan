import { useState, useEffect } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { UploadCloud, Coins, ShieldCheck, Lock } from 'lucide-react'
import UpgradeModal from '../components/UpgradeModal'
import { supabase } from '../lib/supabase'
import './Home.css'

export default function Home() {
  const [activeTab, setActiveTab] = useState<'url' | 'github' | 'zip'>('github')
  const [target, setTarget] = useState('')
  const [pat, setPat] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [credits, setCredits] = useState<number | null>(null)
  const [showUpgradeModal, setShowUpgradeModal] = useState(false)
  const [userId, setUserId] = useState<string | null>(null)
  const navigate = useNavigate()

  const fetchCredits = async (uid: string) => {
    try {
      const baseUrl = import.meta.env.VITE_API_BASE_URL || ''
      const res = await fetch(`${baseUrl}/api/credits?user_id=${uid}`)
      if (res.ok) {
        const data = await res.json()
        setCredits(data.scans_remaining)
      }
    } catch (err) {
      console.error('Failed to fetch credits', err)
    }
  }

  useEffect(() => {
    supabase.auth.getSession().then(({ data: { session } }) => {
      if (session) {
        setUserId(session.user.id)
        fetchCredits(session.user.id)
      }
    })
  }, [])

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

    if (credits !== null && credits <= 0) {
      setShowUpgradeModal(true)
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
      const payload: any = { user_id: session.user.id }

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
      if (!res.ok) {
        if (res.status === 402) {
           setShowUpgradeModal(true)
           setLoading(false)
           return
        }
        throw new Error(data.detail || 'Scan failed to start')
      }
      
      // Successfully started scan
      if (credits !== null) setCredits(credits - 1)
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
    <div className="home-wrapper fade-in">
      <div className="page">
        <div className="col-left">
          <div className="hero-text">
            <div className="kicker">ONE URL · ONE CLICK</div>
            <h1>Total<br/><em>visibility.</em><br/>Instantly.</h1>
            <p className="subtitle">Nine concurrent security modules scan your repository or live URL and return a plain-English risk report — in under sixty seconds.</p>
          </div>
        </div>

        <div className="col-right">
          <div className="form-area">
            <div className="form-header">SCAN TARGET</div>

            <div className="tabs">
              <button 
                className={`tab ${activeTab === 'github' ? 'active' : ''}`}
                onClick={() => { setActiveTab('github'); setTarget(''); setError(''); }}
              >GitHub repo</button>
              <button 
                className={`tab ${activeTab === 'url' ? 'active' : ''}`}
                onClick={() => { setActiveTab('url'); setTarget(''); setError(''); }}
              >Live URL</button>
              <button 
                className={`tab ${activeTab === 'zip' ? 'active' : ''}`}
                onClick={() => { setActiveTab('zip'); setTarget(''); setError(''); }}
              >ZIP file</button>
            </div>

            {error && (
              <div className="text-red-400 mb-4 text-sm bg-red-400/10 p-3 rounded-lg border border-red-500/20 w-full">
                {error}
              </div>
            )}

            {activeTab === 'zip' ? (
               <div className="flex flex-col items-center justify-center p-6 border border-dashed border-[#ffffff14] rounded-lg w-full bg-[#111] hover:bg-[#151515] transition cursor-pointer relative mb-4">
                 <input 
                   type="file" 
                   accept=".zip" 
                   className="absolute inset-0 opacity-0 cursor-pointer" 
                   onChange={handleFileUpload}
                 />
                 <UploadCloud className="w-8 h-8 text-[#e6e6e640] mb-2" />
                 <span className="text-sm text-[#e6e6e640]">
                   {target ? target : 'Click or drop .zip file (Max 50MB)'}
                 </span>
               </div>
            ) : (
              <div className="field">
                <label className="field-label">{activeTab === 'url' ? 'TARGET URL' : 'REPOSITORY URL'}</label>
                <input 
                  type="text" 
                  className="scan-inp" 
                  placeholder={activeTab === 'github' ? 'https://github.com/username/repo' : 'https://yourdomain.com'}
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  onKeyDown={(e) => { if (e.key === 'Enter') handleScan(); }}
                />
              </div>
            )}

            {activeTab === 'github' && (
              <div className="field fade-in" style={{ marginTop: '10px' }}>
                <label className="field-label">PERSONAL ACCESS TOKEN <span style={{opacity: 0.5}}>— OPTIONAL</span></label>
                <input 
                  type="password" 
                  className="scan-inp" 
                  placeholder="For private repositories"
                  value={pat}
                  onChange={e => setPat(e.target.value)}
                />
              </div>
            )}

            {credits !== null && credits >= 0 && (
               <div className="mt-4 flex items-center justify-between bg-[#161616] border border-[#ffffff14] p-3 rounded-md text-sm text-[#e6e6e6cc]">
                  <div className="flex items-center gap-2">
                     <Coins size={14} className="text-[#e6e6e640]" />
                     <span><strong className="text-white">{credits}</strong> scans remaining</span>
                  </div>
                  <button onClick={() => setShowUpgradeModal(true)} className="text-xs text-white hover:underline transition">Upgrade</button>
               </div>
            )}

            <button 
              className="scan-btn" 
              onClick={() => handleScan()}
              disabled={loading}
            >
              <svg width="13" height="13" viewBox="0 0 13 13" fill="currentColor"><path d="M6.5 1L5 5.5H9L5.5 12L7 7.5H3L6.5 1Z"/></svg>
              {loading ? 'Initializing Scan...' : 'Start scan'}
            </button>

            <div className="mt-5 flex items-center justify-center gap-3 text-xs text-[#e6e6e660]">
               <div className="flex items-center gap-1.5 font-medium text-[#e6e6e690]">
                 <ShieldCheck size={14} className="text-green-400" /> SOC 2 Compliant
               </div>
               <span>•</span>
               <div className="flex items-center gap-1 font-medium text-[#e6e6e690]">
                 <Lock size={12} /> Privacy Guaranteed
               </div>
            </div>
          </div>

          <div className="modules-footer">
            <div className="modules-label">ACTIVE MODULES</div>
            <div className="tags">
              <div className="tag">static analysis</div>
              <div className="tag">dependency audit</div>
              <div className="tag">external audit</div>
              <div className="tag">ssl / tls</div>
              <div className="tag">dns scan</div>
              <div className="tag">secret detection</div>
              <div className="tag">auth headers</div>
              <div className="tag">cve database</div>
              <div className="tag">ai auto-fix</div>
            </div>

            <div className="mt-12 flex gap-6 text-[10px] uppercase font-mono tracking-widest text-[#e6e6e640]">
              <Link to="/terms" className="hover:text-white transition">Terms & Conditions</Link>
              <Link to="/privacy" className="hover:text-white transition">Privacy Policy</Link>
            </div>
          </div>
        </div>
      </div>

      {showUpgradeModal && userId && (
        <UpgradeModal 
          userId={userId} 
          onClose={() => setShowUpgradeModal(false)}
          onSuccess={() => fetchCredits(userId)}
        />
      )}
    </div>
  )
}
