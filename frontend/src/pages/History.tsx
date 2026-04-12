import { useEffect, useState } from 'react'
import { supabase } from '../lib/supabase'
import { useNavigate, Link } from 'react-router-dom'
import { Loader2, Shield, ChevronRight, Activity } from 'lucide-react'

export default function History() {
  const [scans, setScans] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const navigate = useNavigate()

  useEffect(() => {
    supabase.auth.getSession().then(({ data: { session } }) => {
      if (!session) {
        navigate('/auth')
      } else {
        fetchHistory(session.user.id)
      }
    })
  }, [navigate])

  const fetchHistory = async (_userId: string) => {
    // Note: If you want user-scoped history, your backend/DB should store `user_id` for scans.
    // Assuming 'scans' table has a 'user_id' column or we just fetch all recent scans.
    const { data } = await supabase
      .from('scans')
      .select('*')
      .eq('user_id', _userId)
      .order('created_at', { ascending: false })
      .limit(50)

    if (data) setScans(data)
    setLoading(false)
  }

  const formatDate = (dateString: string) => {
    const d = new Date(dateString)
    return new Intl.DateTimeFormat('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }).format(d)
  }

  if (loading) return <div className="flex h-[80vh] items-center justify-center"><Loader2 className="w-8 h-8 text-white animate-spin" /></div>

  return (
    <div className="max-w-5xl mx-auto px-4 py-12 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div className="flex items-center gap-3 mb-8 border-b border-[#222] pb-6">
        <Activity className="w-8 h-8 text-white" />
        <div>
          <h1 className="text-2xl font-display font-medium text-white tracking-tight">Scan History</h1>
          <p className="text-gray-500 font-body text-sm mt-1">Review your previously executed security audits.</p>
        </div>
      </div>

      {scans.length === 0 ? (
        <div className="text-center py-20 border border-[#222] rounded-xl bg-[#0a0a0a]">
          <Shield className="w-12 h-12 text-[#333] mx-auto mb-4" />
          <h3 className="text-white font-display text-lg">No history found</h3>
          <p className="text-gray-500 text-sm mt-2">Start a new scan to see it populated here.</p>
          <Link to="/" className="inline-block mt-6 px-4 py-2 bg-white text-black font-semibold rounded-lg text-sm transition-transform hover:scale-105">
            Run a Scan
          </Link>
        </div>
      ) : (
        <div className="bg-[#0a0a0a] border border-[#222] rounded-xl overflow-hidden shadow-2xl">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-[#222] bg-[#111]">
                <th className="px-6 py-4 font-display text-xs text-gray-500 uppercase tracking-widest font-semibold">Target</th>
                <th className="px-6 py-4 font-display text-xs text-gray-500 uppercase tracking-widest font-semibold">Status</th>
                <th className="px-6 py-4 font-display text-xs text-gray-500 uppercase tracking-widest font-semibold">Risk Score</th>
                <th className="px-6 py-4 font-display text-xs text-gray-500 uppercase tracking-widest font-semibold">Date</th>
                <th className="px-6 py-4"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#222]">
              {scans.map((scan) => (
                <tr key={scan.id} className="hover:bg-[#111] transition-colors group">
                  <td className="px-6 py-4">
                    <div className="font-body text-sm text-gray-300 truncate max-w-xs" title={scan.target}>
                      {scan.target}
                    </div>
                  </td>
                  <td className="px-6 py-4">
                     <span className={`inline-flex items-center px-2 py-1 rounded-md text-xs font-display uppercase tracking-widest ${
                       scan.status === 'done' ? 'bg-[#1a2e1d] text-[#2ce870] border border-[#2ce870]/20' :
                       scan.status === 'failed' ? 'bg-[#2a0f14] text-[#ff4d5a] border border-[#ff4d5a]/20' :
                       'bg-[#222] text-gray-300 border border-[#333]'
                     }`}>
                       {scan.status}
                     </span>
                  </td>
                  <td className="px-6 py-4">
                    <div className="font-display font-medium text-lg">
                      {scan.status === 'done' ? (
                        <span className={
                          (scan.risk_score || 0) > 70 ? 'text-[#ff4d5a]' :
                          (scan.risk_score || 0) > 30 ? 'text-[#f0c800]' :
                          'text-[#2ce870]'
                        }>
                          {scan.risk_score}
                        </span>
                      ) : '-'}
                    </div>
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-500 font-body">
                    {formatDate(scan.created_at)}
                  </td>
                  <td className="px-6 py-4 text-right">
                    <Link to={`/results/${scan.id}`} className="inline-flex items-center gap-1 text-xs text-gray-400 group-hover:text-white transition-colors">
                      View <ChevronRight className="w-4 h-4" />
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
