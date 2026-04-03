import { BrowserRouter, Routes, Route, Link, useLocation } from 'react-router-dom'
import { useEffect, useState } from 'react'
import { supabase } from './lib/supabase'
import Home from './pages/Home'
import Results from './pages/Results'
import History from './pages/History'
import Auth from './pages/Auth'
import SharedReport from './pages/SharedReport'
import { Plus, LogIn, LogOut } from 'lucide-react'
import CanvasBackground from './components/CanvasBackground'

function AppShell() {
  const location = useLocation();
  const isLanding = location.pathname === '/';
  const hasSidebar = location.pathname.startsWith('/results') || location.pathname.startsWith('/history');
  const [session, setSession] = useState<any>(null);

  useEffect(() => {
    supabase.auth.getSession().then(({ data: { session } }) => setSession(session));
    const { data: { subscription } } = supabase.auth.onAuthStateChange((_event, session) => setSession(session));
    return () => subscription.unsubscribe();
  }, []);

  const handleLogout = async () => {
    await supabase.auth.signOut();
  }

  return (
    <>
      <CanvasBackground />
      <div id="app-shell">
        <header>
          <nav id="top-nav" aria-label="Main navigation">
            <Link className="nav-logo" to="/" aria-label="ShieldScan — Go to home page">
              <svg width="34" height="38" viewBox="0 0 32 36" fill="none"
                   xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
                <path d="M16 2L28 7.5V18C28 24.5 22.5 30.5 16 33
                         C9.5 30.5 4 24.5 4 18V7.5L16 2Z"
                      stroke="var(--color-primary)" strokeWidth="1.5" fill="none"
                      opacity="0.5"/>
                <path d="M16 6L25 10.5V18C25 23 21 28 16 30
                         C11 28 7 23 7 18V10.5L16 6Z"
                      fill="var(--color-primary)" fillOpacity="0.06"
                      stroke="var(--color-primary)" strokeWidth="1"/>
                <line x1="4" y1="18" x2="28" y2="18"
                      stroke="var(--color-primary)" strokeWidth="0.75"
                      strokeOpacity="0.4"/>
                <line x1="7" y1="14" x2="25" y2="14"
                      stroke="var(--color-primary)" strokeWidth="0.5"
                      strokeOpacity="0.2"/>
              </svg>
              <div className="wordmark">
                <span className="w-shield">Shield</span><span className="w-scan">Scan</span>
              </div>
            </Link>

            <div className="nav-right flex items-center gap-4">
              <div className="nav-status-pill hidden sm:flex" aria-label="9 modules active">
                <span className="status-dot" aria-hidden="true"></span>
                9 Modules Active
              </div>
              
              {session ? (
                <>
                  <Link to="/history" className="btn-ghost text-xs" aria-label="View scan history">
                    History
                  </Link>
                  <button onClick={handleLogout} className="btn-ghost px-2" aria-label="Logout" title="Logout">
                    <LogOut size={16} />
                  </button>
                </>
              ) : (
                <Link to="/auth" className="btn-ghost" aria-label="Login">
                  <LogIn size={16} /> Login
                </Link>
              )}

              <Link to="/" className="btn-primary" aria-label="Start a new scan">
                <Plus size={16} aria-hidden="true" />
                New Scan
              </Link>
            </div>
          </nav>
        </header>

        <div id="main-area" className={hasSidebar ? 'has-sidebar' : ''}>
          <aside id="sidebar" aria-label="Scan results navigation"></aside>
          
          <main id="content-area" tabIndex={-1} className={isLanding ? 'is-landing' : ''}>
            <Routes>
              <Route path="/" element={<Home />} />
              <Route path="/results/:scanId" element={<Results />} />
              <Route path="/history" element={<History />} />
              <Route path="/auth" element={<Auth />} />
              <Route path="/report/:uuid" element={<SharedReport />} />
            </Routes>
          </main>
        </div>
      </div>
      <div id="toast-container" aria-live="polite" aria-atomic="true"></div>
    </>
  )
}

function App() {
  return (
    <BrowserRouter>
      <AppShell />
    </BrowserRouter>
  )
}

export default App
