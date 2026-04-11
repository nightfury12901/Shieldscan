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
        className="relative w-full max-w-[400px] bg-[#1a1a1a] shadow-2xl font-sans"
        style={{ 
          border: '0.5px solid rgba(255,255,255,0.1)', 
          borderRadius: '12px',
          padding: '1.75rem' 
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
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '0.75rem' }}>
          <svg width="15" height="15" viewBox="0 0 15 15" fill="none" style={{ flexShrink: 0, opacity: 0.7 }}>
            <path d="M7.5 1L13 4V8.5C13 11.5 10.5 14 7.5 14.5C4.5 14 2 11.5 2 8.5V4L7.5 1Z" stroke="white" strokeWidth="1" fill="none"/>
          </svg>
          <span style={{ fontSize: '15px', fontWeight: 500, color: '#fff' }}>
            Upgrade required
          </span>
        </div>

        <p style={{ fontSize: '12px', color: 'rgba(255,255,255,0.4)', lineHeight: 1.65, marginBottom: '1.5rem' }}>
          You have exhausted your free scan quota. Unlock 10 additional security scans to continue analyzing your repositories.
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

        {/* Price Box */}
        <div style={{ border: '0.5px solid rgba(255,255,255,0.08)', borderRadius: '8px', padding: '1rem', marginBottom: '1.25rem', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div>
            <p style={{ fontSize: '13px', fontWeight: 500, color: '#fff', margin: '0 0 3px' }}>10 security scans</p>
            <p style={{ fontSize: '11px', color: 'rgba(255,255,255,0.35)', margin: 0 }}>One-time premium pass</p>
          </div>
          <span style={{ fontSize: '22px', fontWeight: 500, color: '#fff', fontFamily: 'monospace' }}>₹9</span>
        </div>

        {/* Purchase Button */}
        <button 
          onClick={handleRazorpayPayment}
          disabled={loading}
          style={{ width: '100%', background: '#fff', color: '#000', border: 'none', borderRadius: '8px', padding: '11px', fontSize: '13px', fontWeight: 500, cursor: loading ? 'not-allowed' : 'pointer', marginBottom: '0.5rem', letterSpacing: '0.02em', opacity: loading ? 0.7 : 1 }}
        >
          {loading ? 'Processing...' : 'Purchase now'}
        </button>

        <p style={{ fontSize: '10px', color: 'rgba(255,255,255,0.4)', textAlign: 'center', margin: '0 0 1rem 0' }}>
          *Note: Billed securely as "AiFast" on your statement
        </p>

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
