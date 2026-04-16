import { useState, useEffect } from 'react'
import { X, Lock, Copy, CheckCircle2, ChevronRight, Globe, Server, Terminal, Shield, Cookie, GitBranch, Zap, AlertTriangle } from 'lucide-react'
import './SslGuideModal.css'

interface RemediationGuideModalProps {
  finding: any
  affectedUrl: string
  onClose: () => void
}

// ─── Guide type detection ───────────────────────────────────────────
type GuideType = 'ssl' | 'headers' | 'cookies' | 'cors' | 'rate_limit' | 'open_redirect' | 'auth' | 'generic'

function detectGuideType(finding: any): GuideType {
  const text = `${finding.title} ${finding.description} ${finding.category}`.toLowerCase()
  if (['ssl', 'tls', 'certificate', 'https', 'hsts', 'cipher', 'expired cert'].some(k => text.includes(k))) return 'ssl'
  if (['content-security-policy', 'csp', 'x-frame', 'x-content-type', 'security header', 'missing header', 'referrer-policy'].some(k => text.includes(k))) return 'headers'
  if (['cookie', 'httponly', 'samesite', 'secure flag'].some(k => text.includes(k))) return 'cookies'
  if (['cors', 'cross-origin', 'allow-origin'].some(k => text.includes(k))) return 'cors'
  if (['rate limit', 'rate-limit', 'throttl', 'brute force'].some(k => text.includes(k))) return 'rate_limit'
  if (['open redirect', 'redirect', 'location header'].some(k => text.includes(k))) return 'open_redirect'
  if (['auth', 'login', 'password', 'session', 'jwt', 'credential'].some(k => text.includes(k))) return 'auth'
  return 'generic'
}

const GUIDE_META: Record<GuideType, { label: string; icon: JSX.Element; color: string }> = {
  ssl:           { label: 'SSL / HTTPS Certificate',   icon: <Lock size={15} />,        color: '#2ce870' },
  headers:       { label: 'Security Headers',           icon: <Shield size={15} />,      color: '#a78bfa' },
  cookies:       { label: 'Cookie Security',            icon: <Cookie size={15} />,      color: '#f0c800' },
  cors:          { label: 'CORS Policy',                icon: <GitBranch size={15} />,   color: '#63b3ed' },
  rate_limit:    { label: 'Rate Limiting',              icon: <Zap size={15} />,         color: '#ff8c38' },
  open_redirect: { label: 'Open Redirect Fix',          icon: <AlertTriangle size={15}/>,color: '#ff4d5a' },
  auth:          { label: 'Authentication Hardening',   icon: <Lock size={15} />,        color: '#f0c800' },
  generic:       { label: 'Security Remediation Guide', icon: <Shield size={15} />,      color: '#9ca3af' },
}

type ServerType = 'nginx' | 'apache' | 'node' | 'standalone' | 'unknown'

const SERVER_OPTIONS: { value: ServerType; label: string; icon: string }[] = [
  { value: 'nginx',      label: 'Nginx',                   icon: '🟢' },
  { value: 'apache',     label: 'Apache',                  icon: '🔴' },
  { value: 'node',       label: 'Node.js / Express',       icon: '🟡' },
  { value: 'standalone', label: 'Standalone / Other',      icon: '⚙️' },
  { value: 'unknown',    label: "I don't know",             icon: '❓' },
]

interface StepData { title: string; description: string; code?: string }

// ─── Step generators per guide type ────────────────────────────────

function getSslSteps(server: ServerType, domain: string): StepData[] {
  const d = domain || 'yourdomain.com'
  const installStep: StepData = { title: 'Install Certbot', description: 'Certbot is the official Let\'s Encrypt client. Run on Ubuntu/Debian:', code: 'sudo apt update && sudo apt install -y certbot' }
  const renewStep:   StepData = { title: 'Test Auto-Renewal', description: 'Certificates expire every 90 days. Verify renewal works:', code: 'sudo certbot renew --dry-run' }
  const verifyStep:  StepData = { title: 'Verify Your Certificate', description: `Check your cert with SSL Labs:`, code: `curl -I https://${d}\n# Or visit:\nhttps://www.ssllabs.com/ssltest/analyze.html?d=${d}` }
  if (server === 'nginx') return [installStep, { title: 'Install Nginx Plugin', description: '', code: 'sudo apt install -y python3-certbot-nginx' }, { title: 'Obtain & Install', description: 'Certbot auto-edits your nginx.conf to redirect HTTP → HTTPS:', code: `sudo certbot --nginx -d ${d} -d www.${d}` }, { title: 'Reload Nginx', description: '', code: 'sudo systemctl reload nginx' }, renewStep, verifyStep]
  if (server === 'apache') return [installStep, { title: 'Install Apache Plugin', description: '', code: 'sudo apt install -y python3-certbot-apache' }, { title: 'Obtain & Install', description: 'Certbot auto-edits your virtual host:', code: `sudo certbot --apache -d ${d} -d www.${d}` }, { title: 'Reload Apache', description: '', code: 'sudo systemctl reload apache2' }, renewStep, verifyStep]
  if (server === 'node') return [installStep, { title: 'Get Certificate', description: 'Stop your app temporarily, then run:', code: `sudo certbot certonly --standalone -d ${d}` }, { title: 'Use in Node.js', description: 'Load the cert files in your HTTPS server:', code: `const https = require('https'), fs = require('fs')\nhttps.createServer({\n  key:  fs.readFileSync('/etc/letsencrypt/live/${d}/privkey.pem'),\n  cert: fs.readFileSync('/etc/letsencrypt/live/${d}/fullchain.pem'),\n}, app).listen(443)` }, { title: 'Redirect HTTP → HTTPS', description: '', code: `require('http').createServer((req,res)=>{\n  res.writeHead(301,{Location:'https://'+req.headers.host+req.url})\n  res.end()\n}).listen(80)` }, renewStep, verifyStep]
  // standalone / unknown
  return [installStep, { title: 'Stop Port 80 Service', description: '', code: 'sudo systemctl stop nginx  # or apache2, node' }, { title: 'Get Certificate', description: '', code: `sudo certbot certonly --standalone -d ${d}` }, { title: 'Certificate Files', description: 'Point your server at these files:', code: `/etc/letsencrypt/live/${d}/fullchain.pem\n/etc/letsencrypt/live/${d}/privkey.pem` }, renewStep, verifyStep]
}

function getHeadersSteps(server: ServerType): StepData[] {
  const nginxConf = `# Add inside your server {} block\nadd_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';" always;\nadd_header X-Frame-Options "SAMEORIGIN" always;\nadd_header X-Content-Type-Options "nosniff" always;\nadd_header Referrer-Policy "strict-origin-when-cross-origin" always;\nadd_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;\nadd_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;`
  const apacheConf = `# Add to your VirtualHost or .htaccess\nHeader always set Content-Security-Policy "default-src 'self'"\nHeader always set X-Frame-Options "SAMEORIGIN"\nHeader always set X-Content-Type-Options "nosniff"\nHeader always set Referrer-Policy "strict-origin-when-cross-origin"\nHeader always set Strict-Transport-Security "max-age=31536000; includeSubDomains"\n\n# Enable mod_headers first:\na2enmod headers && systemctl reload apache2`
  const nodeConf = `// Install helmet:\nnpm install helmet\n\n// In your Express app:\nconst helmet = require('helmet')\napp.use(helmet())\n\n// Customise (optional):\napp.use(helmet.contentSecurityPolicy({\n  directives: {\n    defaultSrc: ["'self'"],\n    scriptSrc:  ["'self'"],\n  }\n}))`
  const code = server === 'nginx' ? nginxConf : server === 'apache' ? apacheConf : nodeConf
  return [
    { title: 'What Are Security Headers?', description: 'HTTP security headers tell browsers how to behave when handling your site. Missing headers allow clickjacking, MIME-sniffing, XSS, and data leaks.' },
    { title: 'Add All Required Headers', description: `Apply these headers for your ${server === 'nginx' ? 'Nginx' : server === 'apache' ? 'Apache' : 'Node.js'} setup:`, code },
    { title: 'Test Your Headers', description: 'Use Security Headers to score your site:', code: '# Visit:\nhttps://securityheaders.com/?q=yourdomain.com&followRedirects=on' },
    { title: 'Reload Your Server', description: 'Apply the config change:', code: server === 'nginx' ? 'sudo nginx -t && sudo systemctl reload nginx' : server === 'apache' ? 'sudo apachectl configtest && sudo systemctl reload apache2' : '# Restart your Node process (pm2 restart app, etc.)' },
  ]
}

function getCookieSteps(server: ServerType): StepData[] {
  return [
    { title: 'Why Cookie Flags Matter', description: 'Cookies without HttpOnly can be stolen by XSS. Cookies without Secure are sent over plain HTTP. Cookies without SameSite aid CSRF attacks.' },
    { title: 'Set Flags at the Server', description: 'When you set a cookie, include all three flags:', code: server === 'node'
        ? `// Express + cookie-session / express-session:\napp.use(session({\n  secret: process.env.SESSION_SECRET,\n  cookie: {\n    httpOnly: true,   // prevent JS access\n    secure:   true,   // HTTPS only\n    sameSite: 'strict' // CSRF protection\n  }\n}))`
        : server === 'nginx'
        ? `# Nginx — patch Set-Cookie headers:\nproxy_cookie_flags ~ httponly secure samesite=strict;`
        : `# Apache — add HttpOnly and Secure to all cookies:\nHeader edit Set-Cookie ^(.*)$ "$1; HttpOnly; Secure; SameSite=Strict"` },
    { title: 'Audit Existing Cookies', description: 'Review all cookies your app sets in the DevTools Application → Cookies panel. Each should show ✓ HttpOnly ✓ Secure ✓ SameSite.' },
    { title: 'Verify', description: 'Test with:', code: `curl -I https://yourdomain.com\n# Look for Set-Cookie: ...HttpOnly; Secure; SameSite=Strict` },
  ]
}

function getCorsSteps(): StepData[] {
  return [
    { title: 'What Is a CORS Misconfiguration?', description: 'Setting Access-Control-Allow-Origin: * allows any website to read responses from your API — including authenticated requests if credentials are also allowed. This can leak private user data.' },
    { title: 'Fix: Use an Explicit Allowlist', description: 'Replace the wildcard with your trusted origins:', code: `// Node.js / Express (cors package):\nconst cors = require('cors')\nconst ALLOWED = ['https://yourapp.com', 'https://www.yourapp.com']\napp.use(cors({\n  origin: (origin, cb) => {\n    if (!origin || ALLOWED.includes(origin)) cb(null, true)\n    else cb(new Error('Not allowed by CORS'))\n  },\n  credentials: true,    // only if you need cookies/auth\n}))` },
    { title: 'Never Mix Wildcard with Credentials', description: 'This combination is rejected by browsers AND is a major security risk:', code: `# ❌ INVALID — browsers block this:\nAccess-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true\n\n# ✅ CORRECT:\nAccess-Control-Allow-Origin: https://yourapp.com\nAccess-Control-Allow-Credentials: true` },
    { title: 'Test Your CORS Policy', description: '', code: `curl -H "Origin: https://evil.com" \\\n  -I https://yourapi.com/endpoint\n# Should NOT see evil.com in the response` },
  ]
}

function getRateLimitSteps(server: ServerType): StepData[] {
  return [
    { title: 'Why Rate Limiting Is Critical', description: 'Without rate limiting, attackers can brute-force login endpoints, scrape your API, or trigger denial-of-service by flooding requests.' },
    { title: 'Implement Rate Limiting', description: 'Add limits to sensitive endpoints:', code: server === 'node'
        ? `npm install express-rate-limit\n\n// In your Express app:\nconst rateLimit = require('express-rate-limit')\nconst loginLimiter = rateLimit({\n  windowMs: 15 * 60 * 1000, // 15 minutes\n  max: 10,                   // 10 requests per window\n  message: 'Too many login attempts. Try again later.',\n  standardHeaders: true,\n  legacyHeaders: false,\n})\napp.use('/api/login', loginLimiter)`
        : server === 'nginx'
        ? `# In nginx.conf (http block):\nlimit_req_zone $binary_remote_addr zone=api:10m rate=10r/m;\n\n# In your server block:\nlocation /api/login {\n  limit_req zone=api burst=5 nodelay;\n  # ...your proxy pass\n}`
        : `# Apache with mod_ratelimit:\n<Location "/api/login">\n  SetOutputFilter RATE_LIMIT\n  SetEnv rate-limit 400\n</Location>` },
    { title: 'Also Consider', description: '• Add CAPTCHA on login / registration\n• Block IPs after N failed attempts (fail2ban)\n• Use Cloudflare or similar WAF for production traffic' },
    { title: 'Test It', description: '', code: `# Quickly test with hey or ab:\nnpm install -g hey\nhey -n 20 -c 5 https://yourapp.com/api/login\n# Should see 429 responses after 10 requests` },
  ]
}

function getOpenRedirectSteps(): StepData[] {
  return [
    { title: 'What Is an Open Redirect?', description: 'Your app accepts a user-supplied URL and redirects to it without validation. Attackers use this to send victims to phishing pages from a trusted domain: yoursite.com/login?next=https://evil.com' },
    { title: 'Fix: Allowlist Redirect Destinations', description: 'Never redirect to arbitrary user-supplied URLs. Validate against a list of allowed paths or domains:', code: `// Node.js / Express example:\nconst SAFE_REDIRECTS = ['/dashboard', '/home', '/profile']\n\napp.get('/login', (req, res) => {\n  const next = req.query.next || '/dashboard'\n  // Only allow relative paths from our allowlist\n  if (SAFE_REDIRECTS.includes(next)) {\n    return res.redirect(next)\n  }\n  // Fallback for unknown destinations\n  return res.redirect('/dashboard')\n})` },
    { title: 'Alternative: Relative-Only Redirects', description: 'If you must accept dynamic paths, strip the scheme/host first:', code: `function safeRedirect(url) {\n  // Remove scheme and host — keeps only the path\n  try {\n    const u = new URL(url, 'http://localhost')\n    return u.pathname + u.search\n  } catch {\n    return '/'\n  }\n}` },
    { title: 'Test Your Fix', description: 'Try these requests — they should all land on your own site, NOT redirect to evil.com:', code: `yourdomain.com/login?next=https://evil.com\nyourdomain.com/login?next=//evil.com\nyourdomain.com/login?next=/%2F%2Fevil.com` },
  ]
}

function getAuthSteps(): StepData[] {
  return [
    { title: 'Hash Passwords Properly', description: 'Never store plain text or MD5/SHA1 passwords. Use a slow, salted hash:', code: `// Node.js:\nnpm install bcrypt\nconst bcrypt = require('bcrypt')\nconst ROUNDS = 12\nconst hash  = await bcrypt.hash(plainPassword, ROUNDS)\nconst match = await bcrypt.compare(plainPassword, storedHash)\n\n# Python:\npip install bcrypt\nimport bcrypt\nhash  = bcrypt.hashpw(pwd.encode(), bcrypt.gensalt(rounds=12))\nmatch = bcrypt.checkpw(pwd.encode(), stored_hash)` },
    { title: 'Secure Session Management', description: 'Use unpredictable session IDs, regenerate after login, and expire idle sessions:', code: `// Express-session:\napp.use(session({\n  secret: process.env.SESSION_SECRET,  // strong random value\n  resave: false,\n  saveUninitialized: false,\n  rolling: true,          // reset expiry on activity\n  cookie: { maxAge: 30 * 60 * 1000, httpOnly: true, secure: true }\n}))\n// Regenerate session ID after login:\nreq.session.regenerate(() => {\n  req.session.userId = user.id\n  res.redirect('/dashboard')\n})` },
    { title: 'Secure JWT Usage', description: 'If using JWTs, set short expiry and sign with a strong secret:', code: `const jwt = require('jsonwebtoken')\nconst token = jwt.sign(\n  { userId: user.id },\n  process.env.JWT_SECRET,  // ≥ 256-bit random value\n  { expiresIn: '15m', algorithm: 'HS256' }\n)\n// Always verify:\nconst payload = jwt.verify(token, process.env.JWT_SECRET)` },
    { title: 'Add Multi-Factor Authentication', description: '• Use TOTP (Google Authenticator / Authy) via the "speakeasy" npm package\n• Offer WebAuthn / passkeys as a modern alternative\n• Never send OTP codes over SMS alone (SIM-swap attacks)' },
  ]
}

function getGenericSteps(finding: any): StepData[] {
  const steps = (finding.fix_steps || '').split('\n').filter((l: string) => l.trim())
  return [
    { title: 'Vulnerability Summary', description: finding.description },
    ...steps.map((step: string, i: number) => ({
      title: `Step ${i + 1}`,
      description: step.replace(/^\d+\.\s*/, ''),
    })),
    { title: 'Verify the Fix', description: 'After applying the remediation, re-run a ShieldScan scan on your updated code or URL to confirm the finding is resolved.' },
  ]
}

function getSteps(guideType: GuideType, server: ServerType, domain: string, finding: any): StepData[] {
  switch (guideType) {
    case 'ssl':          return getSslSteps(server, domain)
    case 'headers':      return getHeadersSteps(server)
    case 'cookies':      return getCookieSteps(server)
    case 'cors':         return getCorsSteps()
    case 'rate_limit':   return getRateLimitSteps(server)
    case 'open_redirect':return getOpenRedirectSteps()
    case 'auth':         return getAuthSteps()
    default:             return getGenericSteps(finding)
  }
}

// ─── Needs server-type picker? ──────────────────────────────────────
const NEEDS_SERVER: GuideType[] = ['ssl', 'headers', 'cookies', 'rate_limit']

// ─── Code block with copy ───────────────────────────────────────────
function CodeBlock({ code }: { code: string }) {
  const [copied, setCopied] = useState(false)
  const handleCopy = async () => {
    await navigator.clipboard.writeText(code)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }
  return (
    <div className="ssl-code-block">
      <button className="ssl-copy-btn" onClick={handleCopy}>
        {copied ? <CheckCircle2 size={13} /> : <Copy size={13} />}
        {copied ? 'Copied!' : 'Copy'}
      </button>
      <pre><code>{code}</code></pre>
    </div>
  )
}

// ─── Main modal ─────────────────────────────────────────────────────
export default function RemediationGuideModal({ finding, affectedUrl, onClose }: RemediationGuideModalProps) {
  const guideType = detectGuideType(finding)
  const meta = GUIDE_META[guideType]
  const needsServer = NEEDS_SERVER.includes(guideType)

  const [serverType, setServerType] = useState<ServerType | null>(needsServer ? null : 'unknown')
  const [activeStep, setActiveStep] = useState(0)

  const domain = (() => { try { return new URL(affectedUrl).hostname } catch { return affectedUrl } })()
  const steps = serverType ? getSteps(guideType, serverType, domain, finding) : []

  useEffect(() => {
    const handleKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    document.addEventListener('keydown', handleKey)
    document.body.style.overflow = 'hidden'
    return () => { document.removeEventListener('keydown', handleKey); document.body.style.overflow = '' }
  }, [onClose])

  return (
    <div className="ssl-modal-overlay" role="dialog" aria-modal="true" aria-label="Remediation Guide">
      <div className="ssl-modal-backdrop" onClick={onClose} />
      <div className="ssl-modal-container">
        {/* Header */}
        <div className="ssl-modal-header">
          <div className="ssl-modal-header-left">
            <div className="ssl-modal-icon-wrap" style={{ borderColor: `${meta.color}44`, background: `${meta.color}14`, color: meta.color }}>
              {meta.icon}
            </div>
            <div>
              <div className="ssl-modal-title">{meta.label}</div>
              <div className="ssl-modal-subtitle">
                <Globe size={11} />
                <span>{domain}</span>
              </div>
            </div>
          </div>
          <button className="ssl-modal-close" onClick={onClose} aria-label="Close"><X size={16} /></button>
        </div>

        {/* Body */}
        <div className="ssl-modal-body">
          {!serverType ? (
            <div className="ssl-server-picker">
              <div className="ssl-picker-heading">
                <Server size={15} />
                What type of web server are you using?
              </div>
              <div className="ssl-picker-description">
                We'll generate the exact commands for your stack. Choose "I don't know" for a universal guide.
              </div>
              <div className="ssl-server-options">
                {SERVER_OPTIONS.map(opt => (
                  <button key={opt.value} className="ssl-server-option" onClick={() => { setServerType(opt.value); setActiveStep(0) }} id={`remediation-server-${opt.value}`}>
                    <span className="ssl-option-icon">{opt.icon}</span>
                    <span className="ssl-option-label">{opt.label}</span>
                    <ChevronRight size={14} className="ssl-option-arrow" />
                  </button>
                ))}
              </div>
            </div>
          ) : (
            <div className="ssl-guide-layout">
              <div className="ssl-steps-sidebar">
                {needsServer && (
                  <button className="ssl-back-btn" onClick={() => { setServerType(null); setActiveStep(0) }}>← Change Server</button>
                )}
                <div className="ssl-steps-list">
                  {steps.map((step, i) => (
                    <button key={i} className={`ssl-step-btn ${activeStep === i ? 'active' : ''} ${i < activeStep ? 'done' : ''}`} onClick={() => setActiveStep(i)} id={`remediation-step-${i}`}>
                      <span className="ssl-step-num">{i < activeStep ? <CheckCircle2 size={13} /> : i + 1}</span>
                      <span className="ssl-step-label">{step.title}</span>
                    </button>
                  ))}
                </div>
              </div>
              <div className="ssl-step-content">
                <div className="ssl-step-badge"><Terminal size={12} />Step {activeStep + 1} of {steps.length}</div>
                <h3 className="ssl-step-title">{steps[activeStep].title}</h3>
                <p className="ssl-step-desc" style={{ whiteSpace: 'pre-line' }}>{steps[activeStep].description}</p>
                {steps[activeStep].code && <CodeBlock code={steps[activeStep].code!} />}
                <div className="ssl-step-nav">
                  {activeStep > 0 && (
                    <button className="ssl-nav-btn secondary" onClick={() => setActiveStep(p => p - 1)}>← Previous</button>
                  )}
                  {activeStep < steps.length - 1 ? (
                    <button className="ssl-nav-btn primary" onClick={() => setActiveStep(p => p + 1)} id="remediation-next-btn" style={{ background: `linear-gradient(135deg, ${meta.color}, ${meta.color}88)` }}>
                      Next Step →
                    </button>
                  ) : (
                    <button className="ssl-nav-btn primary" onClick={onClose} style={{ background: `linear-gradient(135deg, ${meta.color}, ${meta.color}88)` }}>
                      <CheckCircle2 size={14} /> Done ✓
                    </button>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="ssl-modal-footer">
          <Shield size={11} />
          ShieldScan remediation guides are generated based on industry best practices (OWASP, CIS, NIST). Always test in a staging environment first.
        </div>
      </div>
    </div>
  )
}
