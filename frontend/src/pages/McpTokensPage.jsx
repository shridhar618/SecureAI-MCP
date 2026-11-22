import { useEffect, useState, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { format } from 'date-fns'
import { KeyRound, RefreshCw, Ban, Copy, Check, X, Plus } from 'lucide-react'
import ConfirmDialog from '../components/ConfirmDialog'
import api from '../utils/api'

const STATUS_STYLES = {
  active: 'text-success bg-success/10 border-success/20',
  expired: 'text-warn bg-warn/10 border-warn/20',
  revoked: 'text-slate-500 bg-white/5 border-white/10',
}

function StatusBadge({ status }) {
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${STATUS_STYLES[status] || STATUS_STYLES.revoked}`}>
      {status.toUpperCase()}
    </span>
  )
}

const fmt = (value) => (value ? format(new Date(value), 'MMM d, yyyy HH:mm') : '—')

export default function McpTokensPage() {
  const [tokens, setTokens] = useState([])
  const [users, setUsers] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [form, setForm] = useState({ username: '', label: '', days: 30 })
  const [creating, setCreating] = useState(false)
  const [formError, setFormError] = useState('')
  const [created, setCreated] = useState(null) // holds the one-time raw token
  const [copied, setCopied] = useState('')
  const [confirmRevoke, setConfirmRevoke] = useState(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const [tokRes, userRes] = await Promise.all([api.get('/mcp/tokens'), api.get('/users')])
      setTokens(tokRes.data.tokens || [])
      const list = Array.isArray(userRes.data) ? userRes.data : userRes.data.users || []
      setUsers(list.filter((u) => u.is_active !== false))
    } catch (err) {
      setError(err.response?.data?.error || "Couldn't load MCP tokens.")
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const create = async (e) => {
    e.preventDefault()
    setFormError('')
    setCreating(true)
    try {
      const res = await api.post('/mcp/tokens', {
        username: form.username.trim(),
        label: form.label.trim(),
        days: Number(form.days),
      })
      setCreated(res.data.token)
      setForm({ username: '', label: '', days: 30 })
      load()
    } catch (err) {
      setFormError(err.response?.data?.error || 'Could not create the token.')
    } finally {
      setCreating(false)
    }
  }

  const revoke = async (token) => {
    try {
      await api.post(`/mcp/tokens/${token.id}/revoke`)
    } finally {
      load()
    }
  }

  const copy = async (key, text) => {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(key)
      setTimeout(() => setCopied(''), 1500)
    } catch {
      // clipboard can be blocked; the text is selectable in the box as a fallback
    }
  }

  const command = created
    ? `claude mcp add secureai -e SECUREAI_MCP_TOKEN=${created.token} -- /path/to/SecureAI-MCP/backend/venv311/bin/python -m app.mcp_server`
    : ''

  return (
    <div className="h-full overflow-y-auto p-6 space-y-5">
      <motion.div initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }} className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">MCP Tokens</h1>
          <p className="text-xs text-slate-500 mt-0.5">
            Access tokens for AI clients (Claude Desktop, Claude Code) using SecureAI's MCP server. A token has exactly the permissions of its owner.
          </p>
        </div>
        <button onClick={load} title="Refresh" className="w-9 h-9 rounded-lg bg-white/5 border border-white/10 flex items-center justify-center text-slate-400 hover:text-accent transition-colors">
          <RefreshCw size={14} />
        </button>
      </motion.div>

      <form onSubmit={create} className="glass rounded-2xl border border-white/5 p-4 grid gap-3 sm:grid-cols-[1.2fr_1.2fr_110px_auto] items-end">
        <label className="text-[11px] text-slate-400 space-y-1">
          <span>User</span>
          <input
            list="mcp-token-users" required value={form.username}
            onChange={(e) => setForm({ ...form, username: e.target.value })}
            placeholder="username" className="w-full rounded-lg bg-white/5 border border-white/10 px-3 py-2 text-xs text-slate-200 outline-none focus:border-accent/40"
          />
          <datalist id="mcp-token-users">
            {users.map((u) => <option key={u.id} value={u.username}>{u.role}</option>)}
          </datalist>
        </label>
        <label className="text-[11px] text-slate-400 space-y-1">
          <span>Label (optional)</span>
          <input
            maxLength={80} value={form.label} onChange={(e) => setForm({ ...form, label: e.target.value })}
            placeholder="e.g. claude-code laptop" className="w-full rounded-lg bg-white/5 border border-white/10 px-3 py-2 text-xs text-slate-200 outline-none focus:border-accent/40"
          />
        </label>
        <label className="text-[11px] text-slate-400 space-y-1">
          <span>Valid for (days)</span>
          <input
            type="number" min={1} max={365} required value={form.days}
            onChange={(e) => setForm({ ...form, days: e.target.value })}
            className="w-full rounded-lg bg-white/5 border border-white/10 px-3 py-2 text-xs text-slate-200 outline-none focus:border-accent/40"
          />
        </label>
        <button type="submit" disabled={creating} className="h-[34px] px-4 rounded-lg bg-accent/15 border border-accent/30 text-accent text-xs font-semibold inline-flex items-center gap-1.5 hover:bg-accent/25 transition-colors disabled:opacity-40">
          <Plus size={13} /> {creating ? 'Creating…' : 'Create token'}
        </button>
        {formError && <p className="sm:col-span-4 text-xs text-danger">{formError}</p>}
      </form>

      <div className="glass rounded-2xl border border-white/5 overflow-hidden">
        {loading && <div className="p-10 text-center text-xs text-slate-500">Loading tokens...</div>}
        {!loading && error && <div className="p-10 text-center text-xs text-danger">{error}</div>}
        {!loading && !error && tokens.length === 0 && (
          <div className="p-10 text-center">
            <KeyRound size={28} className="mx-auto text-slate-700 mb-2" />
            <p className="text-sm text-slate-400">No MCP tokens yet</p>
            <p className="text-[11px] text-slate-600 mt-1">Create one above to connect an AI client.</p>
          </div>
        )}
        {!loading && !error && tokens.length > 0 && (
          <div className="ui-table-scroll">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-white/5 text-slate-500 uppercase text-[10px] tracking-wider">
                  <th className="text-left px-4 py-3 font-semibold">#</th>
                  <th className="text-left px-4 py-3 font-semibold">User</th>
                  <th className="text-left px-4 py-3 font-semibold">Label</th>
                  <th className="text-left px-4 py-3 font-semibold">Status</th>
                  <th className="text-left px-4 py-3 font-semibold">Created</th>
                  <th className="text-left px-4 py-3 font-semibold">Expires</th>
                  <th className="text-left px-4 py-3 font-semibold">Last used</th>
                  <th className="text-right px-4 py-3 font-semibold">Actions</th>
                </tr>
              </thead>
              <tbody>
                {tokens.map((t) => (
                  <tr key={t.id} className="border-b border-white/5 last:border-0 hover:bg-white/[0.02] transition-colors">
                    <td className="px-4 py-3 text-slate-500 font-mono">{t.id}</td>
                    <td className="px-4 py-3 text-slate-200 font-medium">{t.username} <span className="text-slate-600 font-normal">({t.role})</span></td>
                    <td className="px-4 py-3 text-slate-400">{t.label || '—'}</td>
                    <td className="px-4 py-3"><StatusBadge status={t.status} /></td>
                    <td className="px-4 py-3 text-slate-500">{fmt(t.created_at)}</td>
                    <td className="px-4 py-3 text-slate-500">{fmt(t.expires_at)}</td>
                    <td className="px-4 py-3 text-slate-500">{fmt(t.last_used_at)}</td>
                    <td className="px-4 py-3">
                      <div className="flex justify-end">
                        {t.status === 'active' && (
                          <button title="Revoke" onClick={() => setConfirmRevoke(t)} className="w-7 h-7 rounded-lg bg-white/5 hover:bg-danger/10 flex items-center justify-center text-slate-400 hover:text-danger transition-colors">
                            <Ban size={13} />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <AnimatePresence>
        {created && (
          <>
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="fixed inset-0 bg-black/60 z-40" />
            <motion.div
              role="dialog" aria-modal="true" aria-label="New MCP token"
              initial={{ opacity: 0, scale: 0.96, y: 8 }} animate={{ opacity: 1, scale: 1, y: 0 }} exit={{ opacity: 0, scale: 0.96, y: 8 }}
              className="fixed z-50 left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 w-[94%] max-w-xl glass border border-white/10 rounded-2xl p-5 space-y-3"
            >
              <div className="flex items-start justify-between">
                <div>
                  <h2 className="text-sm font-bold text-white">Token created for {created.username}</h2>
                  <p className="text-[11px] text-warn mt-0.5">Copy it now. For security it is shown only once and can't be retrieved later.</p>
                </div>
                <button onClick={() => setCreated(null)} aria-label="Close" className="w-8 h-8 rounded-lg bg-white/5 flex items-center justify-center text-slate-400 hover:text-white">
                  <X size={14} />
                </button>
              </div>
              <div>
                <p className="text-[10px] uppercase tracking-wider text-slate-500 mb-1">Token</p>
                <div className="flex gap-2">
                  <code className="flex-1 break-all rounded-lg bg-black/30 border border-white/10 px-3 py-2 text-[11px] text-slate-200 select-all">{created.token}</code>
                  <button onClick={() => copy('token', created.token)} className="h-9 px-3 rounded-lg bg-white/5 border border-white/10 text-slate-300 hover:text-accent text-[11px] inline-flex items-center gap-1.5">
                    {copied === 'token' ? <Check size={12} /> : <Copy size={12} />} {copied === 'token' ? 'Copied' : 'Copy'}
                  </button>
                </div>
              </div>
              <div>
                <p className="text-[10px] uppercase tracking-wider text-slate-500 mb-1">Register with Claude Code (adjust the path)</p>
                <div className="flex gap-2">
                  <code className="flex-1 break-all rounded-lg bg-black/30 border border-white/10 px-3 py-2 text-[11px] text-slate-300 select-all">{command}</code>
                  <button onClick={() => copy('cmd', command)} className="h-9 px-3 rounded-lg bg-white/5 border border-white/10 text-slate-300 hover:text-accent text-[11px] inline-flex items-center gap-1.5">
                    {copied === 'cmd' ? <Check size={12} /> : <Copy size={12} />} {copied === 'cmd' ? 'Copied' : 'Copy'}
                  </button>
                </div>
              </div>
              <button onClick={() => setCreated(null)} className="w-full h-9 rounded-lg bg-accent/15 border border-accent/30 text-accent text-xs font-semibold hover:bg-accent/25">
                I've saved it
              </button>
            </motion.div>
          </>
        )}
      </AnimatePresence>

      <ConfirmDialog
        open={!!confirmRevoke}
        danger
        title="Revoke this token?"
        message={confirmRevoke ? `Token #${confirmRevoke.id} for ${confirmRevoke.username} will stop working immediately. Any AI client using it will lose access.` : ''}
        confirmLabel="Revoke"
        onCancel={() => setConfirmRevoke(null)}
        onConfirm={() => { const t = confirmRevoke; setConfirmRevoke(null); revoke(t) }}
      />
    </div>
  )
}
