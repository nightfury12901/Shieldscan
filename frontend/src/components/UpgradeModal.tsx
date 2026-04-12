import { useState } from 'react'
import { AlertCircle, CheckCircle } from 'lucide-react'

interface UpgradeModalProps {
  userId: string
  onClose: () => void
  onSuccess: () => void
}

export default function UpgradeModal({ userId, onClose, onSuccess }: UpgradeModalProps) {
  const [promoCode, setPromoCode] = useState('')
  const [loading, setLoading] = useState(false)
  const [promoLoading, setPromoLoading] = useState(false)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')

  const handleRazorpayPayment = async () => {
    setError('')
    setMessage('')
    setLoading(true)

    try {
      const baseUrl = import.meta.env.VITE_API_BASE_URL || ''
      
      // 1. Create order
      const orderRes = await fetch(`${baseUrl}/api/payment/create-order`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user_id: userId })
      })
      const orderData = await orderRes.json()

      if (!orderRes.ok) throw new Error(orderData.detail || 'Failed to create order')

      // 2. Open Razorpay Checkout
      const options = {
        key: import.meta.env.VITE_RAZORPAY_KEY_ID || '', // Optional if passing from backend, but better here
        amount: orderData.amount,
        currency: orderData.currency,
        name: "ShieldScan Premium",
        description: "10 Security Scans",
        order_id: orderData.order_id,
        handler: async function (response: any) {
          try {
            // 3. Verify Payment
            const verifyRes = await fetch(`${baseUrl}/api/payment/verify`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                user_id: userId,
                razorpay_order_id: response.razorpay_order_id,
                razorpay_payment_id: response.razorpay_payment_id,
                razorpay_signature: response.razorpay_signature
              })
            })
            const verifyData = await verifyRes.json()
            if (!verifyRes.ok) throw new Error(verifyData.detail || 'Verification failed')

            setMessage(`Payment successful! You received ${verifyData.credits_added} credits.`)
            setTimeout(() => {
              onSuccess()
              onClose()
            }, 2000)
          } catch (err: any) {
            setError(err.message)
          }
        },
        prefill: {
          name: "ShieldScan User"
        },
        theme: {
          color: "#9d4edd"
        }
      }

      const rzp = new (window as any).Razorpay(options)
      rzp.on('payment.failed', function (response: any) {
        setError(response.error.description)
      })
      rzp.open()
    } catch (err: any) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const handleApplyPromo = async () => {
    if (!promoCode.trim()) return

    setError('')
    setMessage('')
    setPromoLoading(true)

    try {
      const baseUrl = import.meta.env.VITE_API_BASE_URL || ''
      const res = await fetch(`${baseUrl}/api/payment/apply-promo`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user_id: userId, promo_code: promoCode })
      })

      const data = await res.json()
      if (!res.ok) throw new Error(data.detail || 'Failed to apply promo code')

      setMessage(data.message)
      setTimeout(() => {
        onSuccess()
        onClose()
      }, 2000)
    } catch (err: any) {
      setError(err.message)
    } finally {
      setPromoLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/90 p-4 animate-in fade-in duration-200">
      <div 
        className="upgrade-modal-content relative w-full bg-[#1a1a1a] shadow-2xl font-sans"
        style={{ 
          border: '0.5px solid rgba(255,255,255,0.1)', 
          borderRadius: '12px'
        }}
      >
        
        {/* Close Button */}
        <button 
          onClick={onClose}
          style={{ position: 'absolute', top: '1rem', right: '1rem', background: 'none', border: 'none', color: 'rgba(255,255,255,0.3)', fontSize: '16px', cursor: 'pointer', lineHeight: 1, padding: '4px' }}
        >
          ✕
        </button>

        {/* Title */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '0.5rem' }}>
          <svg width="20" height="20" viewBox="0 0 15 15" fill="none" style={{ flexShrink: 0, opacity: 0.9 }}>
            <path d="M7.5 1L13 4V8.5C13 11.5 10.5 14 7.5 14.5C4.5 14 2 11.5 2 8.5V4L7.5 1Z" stroke="white" strokeWidth="1" fill="none"/>
          </svg>
          <span style={{ fontSize: '18px', fontWeight: 600, color: '#fff' }}>
            Choose your plan
          </span>
        </div>

        <p style={{ fontSize: '13px', color: 'rgba(255,255,255,0.6)', lineHeight: 1.65, marginBottom: '2rem' }}>
          You have exhausted your 3 free scans. Unlock additional security scans to continue analyzing your repositories.
        </p>

        {error && (
           <div style={{ padding: '10px', backgroundColor: 'rgba(239,68,68,0.1)', border: '0.5px solid rgba(239,68,68,0.2)', borderRadius: '8px', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '8px' }}>
             <AlertCircle size={14} color="#ef4444" />
             <span style={{ fontSize: '12px', color: '#f87171' }}>{error}</span>
           </div>
        )}

        {message && (
           <div style={{ padding: '10px', backgroundColor: 'rgba(16,185,129,0.1)', border: '0.5px solid rgba(16,185,129,0.2)', borderRadius: '8px', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '8px' }}>
             <CheckCircle size={14} color="#10b981" />
             <span style={{ fontSize: '12px', color: '#34d399' }}>{message}</span>
           </div>
        )}

        {/* Pricing Cards Container */}
        <div className="pricing-cards-container">
          
          {/* Left Card (₹199) */}
          <div style={{ flex: '1 1 280px', border: '1.5px solid #3b82f6', borderRadius: '12px', padding: '1.5rem', position: 'relative', display: 'flex', flexDirection: 'column', background: 'rgba(255,255,255,0.02)' }}>
            <div style={{ position: 'absolute', top: '-12px', left: '1.5rem', background: '#1e3a8a', color: '#93c5fd', fontSize: '12px', fontWeight: 500, padding: '4px 12px', borderRadius: '16px' }}>
              best seller
            </div>
            <div style={{ fontSize: '11px', color: '#9ca3af', fontWeight: 700, letterSpacing: '0.05em', marginBottom: '0.5rem', marginTop: '0.5rem' }}>ONE-TIME SCAN</div>
            <div style={{ fontSize: '42px', fontWeight: 700, color: '#fff', lineHeight: 1 }}>₹199</div>
            <div style={{ fontSize: '14px', color: '#9ca3af', marginBottom: '1.5rem', marginTop: '0.5rem' }}>for 5 scans</div>
            
            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px', flex: 1, marginBottom: '2rem' }}>
              <div style={{ fontSize: '14px', color: '#d1d5db', borderBottom: '1px solid rgba(255,255,255,0.1)', paddingBottom: '14px' }}>full report, all issues</div>
              <div style={{ fontSize: '14px', color: '#d1d5db', borderBottom: '1px solid rgba(255,255,255,0.1)', paddingBottom: '14px' }}>severity labels (critical/high/low)</div>
              <div style={{ fontSize: '14px', color: '#d1d5db', borderBottom: '1px solid rgba(255,255,255,0.1)', paddingBottom: '14px' }}>PDF download</div>
              <div style={{ fontSize: '14px', color: '#d1d5db' }}>1 GitHub PR auto-fix</div>
            </div>

            <button 
              onClick={handleRazorpayPayment}
              disabled={loading}
              style={{ width: '100%', background: '#fff', color: '#000', border: 'none', borderRadius: '8px', padding: '14px', fontSize: '15px', fontWeight: 600, cursor: loading ? 'not-allowed' : 'pointer', letterSpacing: '0.02em', opacity: loading ? 0.7 : 1 }}
            >
              {loading ? 'Processing...' : 'Get 5 Scans'}
            </button>
            <p style={{ fontSize: '11px', color: 'rgba(255,255,255,0.4)', textAlign: 'center', marginTop: '1rem', marginBottom: 0 }}>
              *Note: Billed securely as "AiFast"
            </p>
          </div>

          {/* Right Card (₹499) */}
          <div style={{ flex: '1 1 280px', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '12px', padding: '1.5rem', background: 'rgba(255,255,255,0.04)', display: 'flex', flexDirection: 'column' }}>
            <div style={{ fontSize: '11px', color: '#9ca3af', fontWeight: 700, letterSpacing: '0.05em', marginBottom: '0.5rem', marginTop: '0.5rem' }}>MONTHLY</div>
            <div style={{ fontSize: '42px', fontWeight: 700, color: '#fff', lineHeight: 1 }}>₹499</div>
            <div style={{ fontSize: '14px', color: '#9ca3af', marginBottom: '1.5rem', marginTop: '0.5rem' }}>per month</div>
            
            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px', flex: 1, marginBottom: '2rem' }}>
               <div style={{ fontSize: '14px', color: '#d1d5db', borderBottom: '1px solid rgba(255,255,255,0.1)', paddingBottom: '14px' }}>unlimited scans</div>
               <div style={{ fontSize: '14px', color: '#d1d5db', borderBottom: '1px solid rgba(255,255,255,0.1)', paddingBottom: '14px' }}>unlimited PR fixes</div>
               <div style={{ fontSize: '14px', color: '#d1d5db', borderBottom: '1px solid rgba(255,255,255,0.1)', paddingBottom: '14px' }}>weekly auto-scan</div>
               <div style={{ fontSize: '14px', color: '#d1d5db' }}>email alerts</div>
            </div>

            <button 
              disabled={true}
              style={{ width: '100%', background: 'rgba(255,255,255,0.1)', color: 'rgba(255,255,255,0.4)', border: 'none', borderRadius: '8px', padding: '14px', fontSize: '15px', fontWeight: 600, cursor: 'not-allowed', letterSpacing: '0.02em', marginTop: 'auto' }}
            >
              Coming Soon
            </button>
          </div>
        </div>

        {/* OR Divider */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '1rem' }}>
          <div style={{ flex: 1, height: '0.5px', background: 'rgba(255,255,255,0.08)' }}></div>
          <span style={{ fontSize: '10px', color: 'rgba(255,255,255,0.25)', letterSpacing: '0.1em' }}>OR USE A CODE</span>
          <div style={{ flex: 1, height: '0.5px', background: 'rgba(255,255,255,0.08)' }}></div>
        </div>

        {/* Promo Code input */}
        <div style={{ display: 'flex', gap: '8px', marginBottom: '1.25rem' }}>
          <input 
            placeholder="Promo code" 
            value={promoCode}
            onChange={(e) => setPromoCode(e.target.value.toUpperCase())}
            style={{ flex: 1, background: 'rgba(255,255,255,0.04)', border: '0.5px solid rgba(255,255,255,0.1)', borderRadius: '8px', padding: '9px 12px', color: '#fff', fontSize: '12px', fontFamily: 'monospace', outline: 'none', letterSpacing: '0.06em' }} 
          />
          <button 
            disabled={promoLoading || !promoCode.trim()}
            onClick={handleApplyPromo}
            style={{ background: 'none', border: '0.5px solid rgba(255,255,255,0.15)', borderRadius: '8px', color: 'rgba(255,255,255,0.6)', fontSize: '12px', padding: '9px 14px', cursor: promoLoading || !promoCode.trim() ? 'not-allowed' : 'pointer', whiteSpace: 'nowrap', opacity: (promoLoading || !promoCode.trim()) ? 0.5 : 1 }}
          >
            {promoLoading ? '...' : 'Apply'}
          </button>
        </div>

        {/* Cancel button */}
        <div style={{ textAlign: 'center' }}>
          <button 
            onClick={onClose}
            style={{ background: 'none', border: 'none', color: 'rgba(255,255,255,0.3)', fontSize: '12px', cursor: 'pointer', fontFamily: 'inherit' }}
          >
            Cancel and return
          </button>
        </div>

      </div>
    </div>
  )
}
