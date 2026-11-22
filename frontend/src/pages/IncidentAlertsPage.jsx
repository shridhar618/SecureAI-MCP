import { useEffect, useState, useCallback } from 'react'
import { motion } from 'framer-motion'
import { format } from 'date-fns'
import { BellRing, RefreshCw, CheckCircle2, XCircle, Eye } from 'lucide-react'
import ConfirmDialog from '../components/ConfirmDialog'
import api from '../utils/api'

const MODE_INFO = {
  off: { label: 'Off', desc: 'Nothing is sent or recorded.' },
  dry_run: { label: 'Dry run', desc: 'Records what would be sent. Nothing leaves SecureAI.' },
  live: { label: 'Live', desc: 'Sends real GitHub issues and Slack messages.' },
}

const KIND_LABELS = {
  high_risk_request: 'A single high-risk AI request',
  governance_case_opened: 'A governance case is opened',
}

const STATUS_STYLES = {
  allowed: 'text-success bg-success/10 border-success/20',
  dry_run: 'text-accent bg-accent/10 border-accent/20',
  queued: 'text-warn bg-warn/10 border-warn/20',
  failed: 'text-danger bg-danger/10 border-danger/20',
}

export default function IncidentAlertsPage() {
  const [state, setState] = useState(null)
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState('')
  const [saving, setSaving] = useState(false)
  const [notice, setNotice] = useState(null) // { tone: 'error' | 'ok', text, items? }
  const [confirmLive, setConfirmLive] = useState(false)
  const [preview, setPreview] = useState(null)
  const [previewing, setPreviewing] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    setLoadError('')
    try {
      const res = await api.get('/incident-alerts')
      setState(res.data)
    } catch (err) {
      setLoadError(err.response?.data?.error || "Couldn't load incident alert settings.")
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const setMode = async (mode, confirm = false) => {
    setSaving(true)
    setNotice(null)
    try {
      const res = await api.put('/incident-alerts/mode', { mode, confirm })
      setState(res.data)
      setNotice({ tone: 'ok', text: `Alert mode is now "${MODE_INFO[mode].label}".` })
    } catch (err) {
      const body = err.response?.data || {}
      setNotice({ tone: 'error', text: body.error || 'Could not change the mode.', items: body.missing_env })
    } finally {
      setSaving(false)
    }
  }

  const onPick = (mode) => {
    if (!state || mode === state.mode) return
    if (mode === 'live') setConfirmLive(true)
    else setMode(mode)
  }

  const runPreview = async (kind) => {
    setPreviewing(kind)
    try {
      const res = await api.post('/incident-alerts/preview', { kind })
      setPreview(res.data)
    } catch (err) {
      setNotice({ tone: 'error', text: err.response?.data?.error || 'Could not build a preview.' })
    } finally {
      setPreviewing('')
    }
  }

  const fileOk = state?.config_file?.valid
  const envLocked = state?.mode_source === 'env'
  const canEdit = fileOk && !envLocked
  const missing = (state?.required_env || []).filter((v) => !v.set)

  return (
    <div className="h-full overflow-y-auto p-6 space-y-5">
      <motion.div initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }} className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">Incident Alerts</h1>
          <p className="text-xs text-slate-500 mt-0.5">
            When a risky request or a new governance case happens, SecureAI can open a GitHub issue and message Slack through MCP.
            Messages carry usernames, scores and rule names only, never what a user typed.
          </p>
        </div>
        <button onClick={load} title="Refresh" className="w-9 h-9 rounded-lg bg-white/5 border border-white/10 flex items-center justify-center text-slate-400 hover:text-accent transition-colors">
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
        </button>
      </motion.div>

      {loadError && <div className="glass rounded-xl p-4 text-xs text-danger border border-danger/20">{loadError}</div>}
      {loading && !state && <div className="p-10 text-center text-xs text-slate-500">Loading settings...</div>}

      {state && (
        <>
          {!fileOk && (
            <div className="glass rounded-xl p-4 border border-warn/20 bg-warn/5 text-xs text-warn/90">
              {state.config_file.error}
            </div>
          )}

          <div className="glass rounded-2xl border border-white/5 p-4 space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="text-xs font-bold text-slate-300">Mode</h2>
              {envLocked && (
                <span className="text-[11px] text-warn">Set by the INCIDENT_MCP_MODE environment variable; change it on the server.</span>
              )}
            </div>
            <div className="grid gap-2 sm:grid-cols-3" role="radiogroup" aria-label="Alert mode">
              {Object.entries(MODE_INFO).map(([id, info]) => {
                const active = state.mode === id
                return (
                  <button
                    key={id} role="radio" aria-checked={active} disabled={!canEdit || saving} onClick={() => onPick(id)}
                    className={`text-left rounded-xl border p-3 transition-colors disabled:opacity-50 ${
                      active
                        ? id === 'live' ? 'border-danger/40 bg-danger/10' : 'border-accent/40 bg-accent/10'
                        : 'border-white/10 bg-white/5 hover:border-white/20'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-semibold text-white">{info.label}</span>
                      {active && <span className="text-[10px] font-mono text-slate-400">CURRENT</span>}
                    </div>
                    <p className="text-[11px] text-slate-500 mt-1">{info.desc}</p>
                  </button>
                )
              })}
            </div>
            {notice && (
              <div className={`rounded-lg p-3 text-xs border ${notice.tone === 'ok' ? 'text-success bg-success/5 border-success/20' : 'text-danger bg-danger/5 border-danger/20'}`}>
                {notice.text}
                {notice.items && (
                  <ul className="mt-1.5 font-mono text-[11px] space-y-0.5">
                    {notice.items.map((n) => <li key={n}>• {n}</li>)}
                  </ul>
                )}
              </div>
            )}
          </div>

          {fileOk && (
            <div className="glass rounded-2xl border border-white/5 p-4">
              <h2 className="text-xs font-bold text-slate-300 mb-1">Required settings</h2>
              <p className="text-[11px] text-slate-500 mb-3">
                Environment variables the alert config uses. Only whether each is set is shown, never its value.
                {missing.length > 0 && ' Live mode stays locked until all are set.'}
              </p>
              {state.required_env.length === 0 ? (
                <p className="text-xs text-slate-600">None referenced.</p>
              ) : (
                <div className="flex flex-wrap gap-2">
                  {state.required_env.map((v) => (
                    <span key={v.name} className={`inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-[11px] font-mono ${v.set ? 'text-success border-success/20 bg-success/5' : 'text-slate-400 border-white/10 bg-white/5'}`}>
                      {v.set ? <CheckCircle2 size={12} /> : <XCircle size={12} />} {v.name}
                    </span>
                  ))}
                </div>
              )}
            </div>
          )}

          {fileOk && (
            <div className="glass rounded-2xl border border-white/5 overflow-hidden">
              <h2 className="text-xs font-bold text-slate-300 p-4 pb-2">What fires, and when</h2>
              {state.actions.length === 0 ? (
                <p className="p-4 pt-0 text-xs text-slate-600">No actions configured.</p>
              ) : (
                <div className="ui-table-scroll">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-white/5 text-slate-500 uppercase text-[10px] tracking-wider">
                        <th className="text-left px-4 py-2.5 font-semibold">Action</th>
                        <th className="text-left px-4 py-2.5 font-semibold">Sends to</th>
                        <th className="text-left px-4 py-2.5 font-semibold">Triggered by</th>
                      </tr>
                    </thead>
                    <tbody>
                      {state.actions.map((a) => (
                        <tr key={a.name} className="border-b border-white/5 last:border-0">
                          <td className="px-4 py-2.5 text-slate-200 font-medium">{a.name}</td>
                          <td className="px-4 py-2.5 font-mono text-slate-400">{a.server} · {a.tool}</td>
                          <td className="px-4 py-2.5 text-slate-400">{a.on.map((k) => KIND_LABELS[k] || k).join('; ')}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              <div className="p-4 border-t border-white/5 space-y-2">
                <p className="text-[11px] text-slate-500">Preview exactly what would be sent for a sample incident. Nothing is sent and nothing is recorded.</p>
                <div className="flex flex-wrap gap-2">
                  {Object.entries(KIND_LABELS).map(([kind, label]) => (
                    <button key={kind} onClick={() => runPreview(kind)} disabled={previewing === kind}
                      className="h-8 px-3 rounded-lg bg-white/5 border border-white/10 text-slate-300 hover:text-accent text-[11px] inline-flex items-center gap-1.5 disabled:opacity-40">
                      <Eye size={12} /> Preview: {label}
                    </button>
                  ))}
                </div>
                {preview && (
                  <div className="rounded-lg bg-black/30 border border-white/10 p-3 space-y-2">
                    <p className="text-[10px] uppercase tracking-wider text-slate-500">
                      Sample preview · {KIND_LABELS[preview.kind]} · nothing sent
                    </p>
                    {preview.calls.length === 0 && <p className="text-xs text-slate-500">No actions are configured for this trigger.</p>}
                    {preview.calls.map((c) => (
                      <div key={c.action}>
                        <p className="text-[11px] text-slate-300 font-mono">{c.action} → {c.server}.{c.tool}</p>
                        <pre className="text-[11px] text-slate-400 whitespace-pre-wrap break-words mt-1">{JSON.stringify(c.arguments, null, 2)}</pre>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          <div className="glass rounded-2xl border border-white/5 overflow-hidden">
            <h2 className="text-xs font-bold text-slate-300 p-4 pb-2">Recent alert activity</h2>
            {state.recent.length === 0 ? (
              <div className="p-8 text-center">
                <BellRing size={26} className="mx-auto text-slate-700 mb-2" />
                <p className="text-xs text-slate-500">No alert activity yet.</p>
              </div>
            ) : (
              <div className="ui-table-scroll">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-white/5 text-slate-500 uppercase text-[10px] tracking-wider">
                      <th className="text-left px-4 py-2.5 font-semibold">Time</th>
                      <th className="text-left px-4 py-2.5 font-semibold">Action</th>
                      <th className="text-left px-4 py-2.5 font-semibold">About</th>
                      <th className="text-left px-4 py-2.5 font-semibold">Trigger</th>
                      <th className="text-left px-4 py-2.5 font-semibold">Result</th>
                    </tr>
                  </thead>
                  <tbody>
                    {state.recent.map((r) => (
                      <tr key={r.id} className="border-b border-white/5 last:border-0">
                        <td className="px-4 py-2.5 text-slate-500 whitespace-nowrap">{r.timestamp ? format(new Date(r.timestamp), 'MMM d, HH:mm:ss') : ''}</td>
                        <td className="px-4 py-2.5 font-mono text-slate-300">{r.action}</td>
                        <td className="px-4 py-2.5 text-slate-300">{r.subject}</td>
                        <td className="px-4 py-2.5 text-slate-500">{KIND_LABELS[r.kind] || r.kind}</td>
                        <td className="px-4 py-2.5">
                          <span className={`inline-flex px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${STATUS_STYLES[r.status] || 'text-slate-400 bg-white/5 border-white/10'}`}>
                            {r.status.toUpperCase()}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </>
      )}

      <ConfirmDialog
        open={confirmLive}
        danger
        title="Go live?"
        message="Real GitHub issues and Slack messages will be sent for every high-risk request and new case, using the configured accounts. Switch back to Dry run or Off at any time."
        confirmLabel="Go live"
        onCancel={() => setConfirmLive(false)}
        onConfirm={() => { setConfirmLive(false); setMode('live', true) }}
      />
    </div>
  )
}
