import { useEffect, useState, useCallback } from 'react'
import { motion } from 'framer-motion'
import { format } from 'date-fns'
import { Activity, RefreshCw } from 'lucide-react'
import api from '../utils/api'

const WINDOWS = [
  { id: '24h', label: '24 hours' },
  { id: '7d', label: '7 days' },
  { id: '30d', label: '30 days' },
]

const REASON_LABELS = {
  permission: 'Role lacks permission',
  admin_role: 'Admin role required',
  invalid_args: 'Invalid arguments',
  denied: 'Refused (scope or confirmation)',
  rate_limited: 'Rate limited',
  schema_invalid: 'Malformed call',
  unknown_tool: 'Unknown tool',
  auth: 'Expired / revoked token',
  internal_error: 'Internal error',
  no_rule: 'Tool not permitted',
  unspecified: 'Unspecified',
}

function Stat({ label, value, tone = 'text-white', hint }) {
  return (
    <div className="glass rounded-2xl border border-white/5 p-4">
      <p className="text-[10px] uppercase tracking-wider text-slate-500">{label}</p>
      <p className={`text-2xl font-bold mt-1 ${tone}`}>{value}</p>
      {hint && <p className="text-[11px] text-slate-600 mt-0.5">{hint}</p>}
    </div>
  )
}

function Split({ allowed, denied, max }) {
  const pct = (n) => (max ? `${(n / max) * 100}%` : '0%')
  return (
    <div className="flex h-2 w-full overflow-hidden rounded bg-white/5">
      <div className="bg-success/70" style={{ width: pct(allowed) }} />
      <div className="bg-danger/70" style={{ width: pct(denied) }} />
    </div>
  )
}

function StatusBadge({ status }) {
  const ok = status === 'allowed'
  return (
    <span className={`inline-flex px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${ok ? 'text-success bg-success/10 border-success/20' : 'text-danger bg-danger/10 border-danger/20'}`}>
      {status.toUpperCase()}
    </span>
  )
}

export default function McpActivityPage() {
  const [windowId, setWindowId] = useState('7d')
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const res = await api.get('/mcp/activity', { params: { window: windowId } })
      setData(res.data)
    } catch (err) {
      setError(err.response?.data?.error || "Couldn't load MCP activity.")
    } finally {
      setLoading(false)
    }
  }, [windowId])

  useEffect(() => { load() }, [load])

  const maxTool = data ? Math.max(1, ...data.by_tool.map((t) => t.calls)) : 1
  const maxCaller = data ? Math.max(1, ...data.by_caller.map((c) => c.calls)) : 1
  const maxDay = data ? Math.max(1, ...data.per_day.map((d) => d.allowed + d.denied)) : 1

  return (
    <div className="h-full overflow-y-auto p-6 space-y-5">
      <motion.div initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }} className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-white">MCP Activity</h1>
          <p className="text-xs text-slate-500 mt-0.5">Who is using SecureAI through AI clients, which tools, and what was refused. Built from the audit log.</p>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex rounded-lg border border-white/10 overflow-hidden" role="group" aria-label="Time window">
            {WINDOWS.map((w) => (
              <button
                key={w.id} onClick={() => setWindowId(w.id)} aria-pressed={windowId === w.id}
                className={`px-3 py-1.5 text-xs transition-colors ${windowId === w.id ? 'bg-accent/15 text-accent' : 'text-slate-400 hover:text-white'}`}
              >{w.label}</button>
            ))}
          </div>
          <button onClick={load} title="Refresh" className="w-9 h-9 rounded-lg bg-white/5 border border-white/10 flex items-center justify-center text-slate-400 hover:text-accent transition-colors">
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
          </button>
        </div>
      </motion.div>

      {error && <div className="glass rounded-xl p-4 text-xs text-danger border border-danger/20">{error}</div>}

      {data && (
        <>
          {data.truncated && (
            <div className="glass rounded-xl p-3 border border-warn/20 bg-warn/5 text-xs text-warn/90">
              {data.total_calls.toLocaleString()} calls in this window; the breakdowns below use the most recent {data.analysed.toLocaleString()}.
            </div>
          )}

          <div className="grid gap-3 grid-cols-2 lg:grid-cols-4">
            <Stat label="Total calls" value={data.total_calls.toLocaleString()} />
            <Stat label="Allowed" value={data.allowed.toLocaleString()} tone="text-success" />
            <Stat label="Denied" value={data.denied.toLocaleString()} tone={data.denied ? 'text-danger' : 'text-white'} />
            <Stat label="Denial rate" value={`${(data.denial_rate * 100).toFixed(1)}%`} hint="High values can mean misuse or a misconfigured client" />
          </div>

          {data.total_calls === 0 ? (
            <div className="glass rounded-2xl border border-white/5 p-10 text-center">
              <Activity size={28} className="mx-auto text-slate-700 mb-2" />
              <p className="text-sm text-slate-400">No MCP activity in this window</p>
              <p className="text-[11px] text-slate-600 mt-1">Calls from AI clients using the MCP server will appear here.</p>
            </div>
          ) : (
            <>
              <div className="glass rounded-2xl border border-white/5 p-4">
                <h2 className="text-xs font-bold text-slate-300 mb-3">Calls per day</h2>
                <div className="flex items-end gap-1 h-28" role="img" aria-label="Calls per day, allowed and denied">
                  {data.per_day.map((d) => {
                    const total = d.allowed + d.denied
                    return (
                      <div key={d.date} className="flex-1 flex flex-col justify-end h-full group relative" title={`${d.date}: ${d.allowed} allowed, ${d.denied} denied`}>
                        <div className="w-full bg-danger/70 rounded-t-sm" style={{ height: `${(d.denied / maxDay) * 100}%` }} />
                        <div className={`w-full bg-success/70 ${d.denied ? '' : 'rounded-t-sm'}`} style={{ height: `${(d.allowed / maxDay) * 100}%` }} />
                        {total === 0 && <div className="w-full h-px bg-white/10" />}
                      </div>
                    )
                  })}
                </div>
                <div className="flex justify-between text-[10px] text-slate-600 mt-1.5 font-mono">
                  <span>{data.per_day[0]?.date}</span><span>{data.per_day[data.per_day.length - 1]?.date}</span>
                </div>
                <div className="flex gap-4 text-[10px] text-slate-500 mt-2">
                  <span><span className="inline-block w-2 h-2 rounded-sm bg-success/70 mr-1" />Allowed</span>
                  <span><span className="inline-block w-2 h-2 rounded-sm bg-danger/70 mr-1" />Denied</span>
                </div>
              </div>

              <div className="grid gap-5 lg:grid-cols-2">
                <div className="glass rounded-2xl border border-white/5 p-4">
                  <h2 className="text-xs font-bold text-slate-300 mb-3">By tool</h2>
                  <div className="space-y-3">
                    {data.by_tool.map((t) => (
                      <div key={t.tool}>
                        <div className="flex justify-between text-[11px] mb-1">
                          <span className="font-mono text-slate-200">{t.tool}</span>
                          <span className="text-slate-500">{t.calls} calls{t.denied ? ` · ${t.denied} denied` : ''}</span>
                        </div>
                        <Split allowed={t.allowed} denied={t.denied} max={maxTool} />
                      </div>
                    ))}
                  </div>
                </div>

                <div className="glass rounded-2xl border border-white/5 p-4">
                  <h2 className="text-xs font-bold text-slate-300 mb-3">By caller</h2>
                  <div className="space-y-3">
                    {data.by_caller.map((c) => (
                      <div key={c.username}>
                        <div className="flex justify-between text-[11px] mb-1">
                          <span className="text-slate-200 font-medium">{c.username}</span>
                          <span className="text-slate-500">
                            {c.calls} calls{c.denied ? ` · ${c.denied} denied` : ''} · last {c.last_seen ? format(new Date(c.last_seen), 'MMM d, HH:mm') : '—'}
                          </span>
                        </div>
                        <Split allowed={c.allowed} denied={c.denied} max={maxCaller} />
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {data.denial_reasons.length > 0 && (
                <div className="glass rounded-2xl border border-white/5 p-4">
                  <h2 className="text-xs font-bold text-slate-300 mb-3">Why calls were denied</h2>
                  <div className="flex flex-wrap gap-2">
                    {data.denial_reasons.map((r) => (
                      <span key={r.reason} className="inline-flex items-center gap-2 rounded-lg bg-danger/5 border border-danger/20 px-3 py-1.5 text-[11px] text-slate-300">
                        {REASON_LABELS[r.reason] || r.reason}
                        <span className="font-mono font-bold text-danger">{r.count}</span>
                      </span>
                    ))}
                  </div>
                </div>
              )}

              <div className="glass rounded-2xl border border-white/5 overflow-hidden">
                <h2 className="text-xs font-bold text-slate-300 p-4 pb-2">Recent calls</h2>
                <div className="ui-table-scroll">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-white/5 text-slate-500 uppercase text-[10px] tracking-wider">
                        <th className="text-left px-4 py-2.5 font-semibold">Time</th>
                        <th className="text-left px-4 py-2.5 font-semibold">Caller</th>
                        <th className="text-left px-4 py-2.5 font-semibold">Tool</th>
                        <th className="text-left px-4 py-2.5 font-semibold">Status</th>
                        <th className="text-left px-4 py-2.5 font-semibold">Detail</th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.recent.map((r) => (
                        <tr key={r.id} className="border-b border-white/5 last:border-0 hover:bg-white/[0.02]">
                          <td className="px-4 py-2.5 text-slate-500 whitespace-nowrap">{format(new Date(r.timestamp), 'MMM d, HH:mm:ss')}</td>
                          <td className="px-4 py-2.5 text-slate-200">{r.username}</td>
                          <td className="px-4 py-2.5 font-mono text-slate-300">{r.tool}</td>
                          <td className="px-4 py-2.5"><StatusBadge status={r.status} /></td>
                          <td className="px-4 py-2.5 text-slate-500">
                            {r.reason_code ? (REASON_LABELS[r.reason_code] || r.reason_code) : r.target || ''}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </>
          )}
        </>
      )}
      {loading && !data && <div className="p-10 text-center text-xs text-slate-500">Loading MCP activity...</div>}
    </div>
  )
}
