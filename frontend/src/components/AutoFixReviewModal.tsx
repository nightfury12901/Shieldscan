import { useState, useEffect } from 'react'
import ReactDiffViewer, { DiffMethod } from 'react-diff-viewer-continued'
import { X, GitPullRequest, AlertTriangle, Loader2, CheckCircle2, Edit3, Eye } from 'lucide-react'

interface AutoFixReviewModalProps {
  findingTitle: string
  filePath: string
  originalContent: string
  initialNewContent: string
  scanId: string
  findingId: string
  githubPat: string
  onClose: () => void
  onPrCreated: (prUrl: string) => void
}

export default function AutoFixReviewModal({
  findingTitle,
  filePath,
  originalContent,
  initialNewContent,
  scanId,
  findingId,
  githubPat,
  onClose,
  onPrCreated,
}: AutoFixReviewModalProps) {
  const [newContent, setNewContent] = useState(initialNewContent)
  const [viewMode, setViewMode] = useState<'diff' | 'edit'>('diff')
  const [prStatus, setPrStatus] = useState<'idle' | 'loading' | 'success' | 'error'>('idle')
  const [prError, setPrError] = useState('')
  const [prUrl, setPrUrl] = useState('')

  // Trap focus inside modal
  useEffect(() => {
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', handleKey)
    document.body.style.overflow = 'hidden'
    return () => {
      document.removeEventListener('keydown', handleKey)
      document.body.style.overflow = ''
    }
  }, [onClose])

  const handleCreatePR = async () => {
    setPrStatus('loading')
    setPrError('')
    try {
      const baseUrl = (import.meta as any).env?.VITE_API_BASE_URL || ''
      const res = await fetch(`${baseUrl}/api/autofix/pr`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scan_id: scanId,
          finding_id: findingId,
          github_pat: githubPat,
          new_content: newContent,
        }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail || 'PR creation failed')
      setPrUrl(data.pr_url)
      setPrStatus('success')
      onPrCreated(data.pr_url)
    } catch (err: any) {
      setPrError(err.message)
      setPrStatus('error')
    }
  }

  const diffViewerStyles = {
    variables: {
      dark: {
        diffViewerBackground: '#0a0a0a',
        diffViewerTitleBackground: '#111111',
        addedBackground: '#0a2214',
        addedColor: '#2ce870',
        removedBackground: '#2a0f14',
        removedColor: '#ff4d5a',
        wordAddedBackground: '#0d2e1a',
        wordRemovedBackground: '#2e111a',
        addedGutterBackground: '#0a2214',
        removedGutterBackground: '#2a0f14',
        gutterBackground: '#0a0a0a',
        gutterBackgroundDark: '#111111',
        highlightBackground: '#1c1c1c',
        highlightGutterBackground: '#161616',
        codeFoldBackground: '#111111',
        emptyLineBackground: '#0a0a0a',
        gutterColor: '#555555',
        addedGutterColor: '#2ce870',
        removedGutterColor: '#ff4d5a',
        codeFoldContentColor: '#555555',
        diffViewerTitleColor: '#888888',
        diffViewerTitleBorderColor: '#222222',
        codeFoldGutterBackground: '#111111',
      },
    },
    diffContainer: {
      fontFamily: "'IBM Plex Mono', monospace",
      fontSize: '12.5px',
      lineHeight: '1.65',
    },
    titleBlock: {
      background: '#111111',
      padding: '8px 16px',
      borderBottom: '1px solid #222222',
      fontSize: '11px',
      color: '#888888',
      fontFamily: "'IBM Plex Mono', monospace",
    },
  }

  return (
    <div className="autofix-modal-overlay" role="dialog" aria-modal="true" aria-label="Auto-Fix Review">
      {/* Backdrop */}
      <div className="autofix-modal-backdrop" onClick={onClose} />

      <div className="autofix-modal-container">
        {/* Header */}
        <div className="autofix-modal-header">
          <div className="autofix-modal-header-left">
            <div className="autofix-modal-icon-wrap">
              <GitPullRequest size={16} />
            </div>
            <div>
              <div className="autofix-modal-title">AI Auto-Fix Review</div>
              <div className="autofix-modal-subtitle">
                <code>{filePath}</code>
              </div>
            </div>
          </div>
          <button className="autofix-modal-close" onClick={onClose} aria-label="Close modal">
            <X size={16} />
          </button>
        </div>

        {/* Finding context strip */}
        <div className="autofix-modal-context">
          <AlertTriangle size={13} className="text-warning" />
          <span className="autofix-modal-context-label">Patching:</span>
          <span className="autofix-modal-context-title">{findingTitle}</span>
        </div>

        {/* View mode tabs */}
        <div className="autofix-modal-tabs">
          <button
            className={`autofix-tab-btn ${viewMode === 'diff' ? 'active' : ''}`}
            onClick={() => setViewMode('diff')}
          >
            <Eye size={13} /> Diff View
          </button>
          <button
            className={`autofix-tab-btn ${viewMode === 'edit' ? 'active' : ''}`}
            onClick={() => setViewMode('edit')}
          >
            <Edit3 size={13} /> Edit Patch
          </button>
        </div>

        {/* Content area */}
        <div className="autofix-modal-content">
          {viewMode === 'diff' ? (
            <div className="autofix-diff-wrap">
              <ReactDiffViewer
                oldValue={originalContent}
                newValue={newContent}
                splitView={true}
                useDarkTheme={true}
                compareMethod={DiffMethod.WORDS}
                styles={diffViewerStyles}
                leftTitle={`Original — ${filePath}`}
                rightTitle={`AI Patched — ${filePath}`}
                hideLineNumbers={false}
                showDiffOnly={false}
                extraLinesSurroundingDiff={3}
              />
            </div>
          ) : (
            <div className="autofix-edit-wrap">
              <div className="autofix-edit-label">
                <Edit3 size={12} />
                Edit the patched code below before creating the PR:
              </div>
              <textarea
                className="autofix-edit-textarea"
                value={newContent}
                onChange={(e) => setNewContent(e.target.value)}
                spellCheck={false}
                aria-label="Editable patched code"
              />
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="autofix-modal-footer">
          <div className="autofix-modal-footer-left">
            {prStatus === 'error' && (
              <div className="autofix-error-msg">
                <AlertTriangle size={13} />
                {prError}
              </div>
            )}
            {prStatus === 'success' && prUrl && (
              <a
                href={prUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="autofix-pr-link"
              >
                <CheckCircle2 size={13} />
                PR Created — View on GitHub ↗
              </a>
            )}
          </div>
          <div className="autofix-modal-footer-right">
            <button className="autofix-btn-cancel" onClick={onClose}>
              Cancel
            </button>
            {prStatus !== 'success' && (
              <button
                className="autofix-btn-approve"
                onClick={handleCreatePR}
                disabled={prStatus === 'loading' || !newContent.trim()}
              >
                {prStatus === 'loading' ? (
                  <>
                    <Loader2 size={14} className="animate-spin" />
                    Creating PR…
                  </>
                ) : (
                  <>
                    <GitPullRequest size={14} />
                    {prStatus === 'error' ? 'Retry — Create PR' : 'Approve & Create PR'}
                  </>
                )}
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
