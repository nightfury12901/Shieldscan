import { useEffect, useState } from 'react'
import { supabase } from '../lib/supabase'
import { useNavigate } from 'react-router-dom'
import { Shield, GitBranch as Github } from 'lucide-react'

export default function Auth() {
  const navigate = useNavigate()
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [isSignUp, setIsSignUp] = useState(false)
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')

  useEffect(() => {
    supabase.auth.onAuthStateChange((_event, session) => {
      if (session) {
        navigate('/')
      }
    })
  }, [navigate])

  const handleEmailAuth = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError('')

    try {
      if (isSignUp) {
        const { error } = await supabase.auth.signUp({
          email,
          password,
        })
        if (error) throw error
        setError('Check your email for the confirmation link.')
      } else {
        const { error } = await supabase.auth.signInWithPassword({
          email,
          password,
        })
        if (error) throw error
      }
    } catch (err: any) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const handleGithubLogin = async () => {
    try {
      setLoading(true)
      setError('')
      const { error } = await supabase.auth.signInWithOAuth({
        provider: 'github',
        options: {
          redirectTo: window.location.origin
        }
      })
      if (error) throw error
    } catch (err: any) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex min-h-[80vh] flex-col items-center justify-center py-12 px-4 sm:px-6 lg:px-8 animate-in fade-in zoom-in-95 duration-300">
      <div className="w-full max-w-md space-y-8">
        <div className="flex flex-col items-center">
          <Shield className="w-10 h-10 text-primary mb-4" />
          <h2 className="mt-6 text-center text-2xl font-display font-semibold tracking-tight text-white">
            ShieldScan
          </h2>
          <p className="mt-2 text-center text-sm text-gray-400 font-body">
            {isSignUp ? 'Create a new account' : 'Sign in to your account'}
          </p>
        </div>
        
        <div className="mt-8 bg-[#0a0a0a]/90 border border-[#222222] p-8 rounded-xl backdrop-blur-xl shadow-2xl flex flex-col gap-6">
          {error && (
            <div className={`text-sm p-3 rounded-lg border text-center ${error.includes('Check your email') ? 'bg-green-400/10 border-green-500/20 text-green-400' : 'bg-red-400/10 border-red-500/20 text-red-400'}`}>
              {error}
            </div>
          )}

          <form onSubmit={handleEmailAuth} className="flex flex-col gap-4">
            <div>
              <label className="block text-xs font-display uppercase tracking-widest text-[#888] mb-2 pl-1">Email</label>
              <div className="relative">
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="scan-input !mb-0"
                  style={{ paddingRight: '18px' }}
                  placeholder="name@example.com"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-display uppercase tracking-widest text-[#888] mb-2 pl-1 mt-2">Password</label>
              <div className="relative">
                <input
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="scan-input !mb-0"
                  style={{ paddingRight: '18px' }}
                  placeholder="••••••••"
                />
              </div>
            </div>

            <button 
              type="submit"
              disabled={loading}
              className="btn-start-scan mt-4 w-full"
              style={{ height: '44px' }}
            >
              {loading ? 'Processing...' : isSignUp ? 'Sign Up' : 'Sign In'}
            </button>
          </form>

          <div className="relative mt-2 mb-2">
            <div className="absolute inset-0 flex items-center">
              <div className="w-full border-t border-[#333]"></div>
            </div>
            <div className="relative flex justify-center text-sm">
              <span className="px-2 bg-transparent text-[#666] font-body text-xs" style={{ background: '#0d1117' }}>Or continue with</span>
            </div>
          </div>

          <button 
            type="button"
            onClick={handleGithubLogin}
            disabled={loading}
            className="btn-ghost w-full justify-center"
            style={{ height: '44px', border: '1px solid #333' }}
          >
            <Github size={16} />
            GitHub
          </button>
          
          <div className="text-center mt-2">
            <button 
              type="button"
              onClick={() => { setIsSignUp(!isSignUp); setError(''); }}
              className="text-[#888] hover:text-white text-sm font-body transition-colors"
            >
              {isSignUp ? 'Already have an account? Sign In' : "Don't have an account? Sign Up"}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
