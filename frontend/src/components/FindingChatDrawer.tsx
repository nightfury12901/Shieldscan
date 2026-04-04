import { useState, useEffect, useRef } from 'react'
import { createPortal } from 'react-dom'
import { X, Send, Loader2, Bot, User, MessageSquare, ChevronRight } from 'lucide-react'

interface ChatMessage {
  role: 'user' | 'assistant'
  content: string
}

interface FindingChatDrawerProps {
  finding: {
    id: string
    title: string
    severity: string
    description: string
    fix_steps: string
    affected_asset: string
  }
  onClose: () => void
}

const SUGGESTED_QUESTIONS = [
  "Why is this vulnerability dangerous?",
  "Show me a code example of the fix",
  "How do I test if this is fixed?",
  "What's the business impact if not fixed?",
  "Is this a false positive?",
]

export default function FindingChatDrawer({ finding, onClose }: FindingChatDrawerProps) {
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [input, setInput] = useState('')
  const [sending, setSending] = useState(false)
  const [isOpen, setIsOpen] = useState(false)
  const messagesRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLTextAreaElement>(null)

  // Animate open
  useEffect(() => {
    const timer = setTimeout(() => {
      setIsOpen(true)
      inputRef.current?.focus({ preventScroll: true })
    }, 10)
    return () => clearTimeout(timer)
  }, [])

  // Scroll to bottom on new messages without scrolling the main window
  useEffect(() => {
    if (messages.length > 0 && messagesRef.current) {
      messagesRef.current.scrollTo({
        top: messagesRef.current.scrollHeight,
        behavior: 'smooth'
      })
    }
  }, [messages])

  // Escape to close
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') handleClose()
    }
    document.addEventListener('keydown', handler)
    return () => document.removeEventListener('keydown', handler)
  }, [])

  const handleClose = () => {
    setIsOpen(false)
    setTimeout(onClose, 300)
  }

  const sendMessage = async (text: string) => {
    if (!text.trim() || sending) return
    const userMsg: ChatMessage = { role: 'user', content: text }
    setMessages(prev => [...prev, userMsg])
    setInput('')
    setSending(true)

    // Optimistic empty assistant bubble
    setMessages(prev => [...prev, { role: 'assistant', content: '' }])

    try {
      const baseUrl = (import.meta as any).env?.VITE_API_BASE_URL || ''
      const res = await fetch(`${baseUrl}/api/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          finding_id: finding.id,
          message: text,
          history: messages,
        }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail || 'Chat request failed')

      setMessages(prev => {
        const updated = [...prev]
        updated[updated.length - 1] = { role: 'assistant', content: data.reply }
        return updated
      })
    } catch (err: any) {
      setMessages(prev => {
        const updated = [...prev]
        updated[updated.length - 1] = {
          role: 'assistant',
          content: `Sorry, I encountered an error: ${err.message}. Please try again.`,
        }
        return updated
      })
    } finally {
      setSending(false)
      setTimeout(() => inputRef.current?.focus(), 100)
    }
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    sendMessage(input)
  }

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      sendMessage(input)
    }
  }

  const sevColors: Record<string, string> = {
    critical: 'var(--color-critical)',
    medium: 'var(--color-warning)',
    low: 'var(--color-success)',
  }
  const sevColor = sevColors[finding.severity] || 'var(--color-primary)'

  return createPortal(
    <>
      {/* Drawer */}
      <aside
        className={`chat-drawer ${isOpen ? 'open' : ''}`}
        role="complementary"
        aria-label={`AI Assistant for: ${finding.title}`}
      >
        {/* Header */}
        <div className="chat-drawer-header">
          <div className="chat-drawer-header-top">
            <div className="chat-drawer-bot-badge">
              <Bot size={14} />
              ShieldBot
            </div>
            <button
              className="chat-drawer-close"
              onClick={handleClose}
              aria-label="Close chat"
            >
              <X size={15} />
            </button>
          </div>
          {/* Finding context pill */}
          <div className="chat-drawer-context">
            <div
              className="chat-drawer-context-sev"
              style={{ background: `${sevColor}22`, border: `1px solid ${sevColor}44`, color: sevColor }}
            >
              {finding.severity.toUpperCase()}
            </div>
            <div className="chat-drawer-context-title" title={finding.title}>
              {finding.title}
            </div>
          </div>
        </div>

        {/* Messages */}
        <div className="chat-drawer-messages" ref={messagesRef} role="log" aria-live="polite">
          {messages.length === 0 && (
            <div className="chat-drawer-welcome">
              <div className="chat-drawer-welcome-icon">
                <MessageSquare size={24} />
              </div>
              <div className="chat-drawer-welcome-title">Ask ShieldBot</div>
              <div className="chat-drawer-welcome-sub">
                I'm pre-loaded with this vulnerability's context. Ask me anything about it.
              </div>
              {/* Suggested questions */}
              <div className="chat-suggestions">
                {SUGGESTED_QUESTIONS.map((q, i) => (
                  <button
                    key={i}
                    className="chat-suggestion-btn"
                    onClick={() => sendMessage(q)}
                  >
                    <ChevronRight size={11} />
                    {q}
                  </button>
                ))}
              </div>
            </div>
          )}

          {messages.map((msg, i) => (
            <div
              key={i}
              className={`chat-bubble-wrap ${msg.role}`}
            >
              <div className={`chat-bubble-avatar ${msg.role}`}>
                {msg.role === 'assistant' ? <Bot size={12} /> : <User size={12} />}
              </div>
              <div className={`chat-bubble ${msg.role}`}>
                {msg.content === '' && msg.role === 'assistant' ? (
                  <div className="chat-typing-indicator">
                    <span /><span /><span />
                  </div>
                ) : (
                  <div className="chat-bubble-text">
                    {msg.content.split('\n').map((line, j) => (
                      <span key={j}>
                        {line}
                        {j < msg.content.split('\n').length - 1 && <br />}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>

        {/* Input */}
        <form className="chat-drawer-input-wrap" onSubmit={handleSubmit}>
          <textarea
            ref={inputRef}
            className="chat-input"
            placeholder="Ask about this vulnerability…"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            rows={1}
            disabled={sending}
            aria-label="Chat message input"
          />
          <button
            type="submit"
            className="chat-send-btn"
            disabled={sending || !input.trim()}
            aria-label="Send message"
          >
            {sending ? <Loader2 size={15} className="animate-spin" /> : <Send size={15} />}
          </button>
        </form>
      </aside>
    </>,
    document.body
  )
}
