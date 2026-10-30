import { useEffect, useState } from 'react'
import { Activity, ShieldAlert, ShieldCheck, Cpu, RefreshCw, Upload, Search, Zap, ExternalLink, CircleDot } from 'lucide-react'

type Finding = { type: string; severity: string; evidence: string }
type EventRow = { timestamp?: string; process: string; destination: string; provider: string; action: string; risk_score: number; risk_level: string; finding_count: number; findings: Finding[] }
type Summary = { total_events: number; flagged_events: number; critical_events: number; providers: number; average_risk: number }
const API = (import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000').replace(/\/$/, '')
const emptySummary: Summary = { total_events: 0, flagged_events: 0, critical_events: 0, providers: 0, average_risk: 0 }

export default function App() {
  const [rows, setRows] = useState<EventRow[]>([])
  const [summary, setSummary] = useState<Summary>(emptySummary)
  const [loading, setLoading] = useState(false)
  const [message, setMessage] = useState('')
  const [target, setTarget] = useState('https://api.openai.com/v1/chat/completions')
  const [processName, setProcessName] = useState('python.exe')
  const [content, setContent] = useState('Please summarize this file. api_key=sk-EXAMPLE_DEMO_KEY_1234567890')
  const [explanation, setExplanation] = useState('')
  async function refresh() {
    try {
      const [r, s] = await Promise.all([fetch(API + '/api/analyses'), fetch(API + '/api/summary')])
      if (!r.ok || !s.ok) throw new Error('Backend request failed')
      setRows(await r.json()); setSummary(await s.json()); setMessage('')
    } catch { setMessage('Backend not reachable. Start FastAPI on port 8000, then retry.') }
  }
  useEffect(() => { void refresh() }, [])
  async function loadDemo() {
    setLoading(true)
    try { const r = await fetch(API + '/api/demo', { method: 'POST' }); const d = await r.json(); if (!r.ok) throw new Error(d.detail || 'Demo failed'); await refresh(); setMessage(`Loaded ${d.loaded} safe demo events.`) }
    catch (e) { setMessage(e instanceof Error ? e.message : 'Unable to load demo') }
    finally { setLoading(false) }
  }
  async function socketSnapshot() {
    setLoading(true)
    try {
      const r = await fetch(API + '/api/collector/socket-snapshot', { method: 'POST' })
      const d = await r.json()
      if (!r.ok) throw new Error(d.detail || 'Socket snapshot failed')
      setMessage(`T1 snapshot complete: ${d.events?.length ?? 0} connections observed. Content was not inspected.${d.partial_visibility ? ' Partial visibility: check warnings.' : ''}`)
    } catch (e) { setMessage(e instanceof Error ? e.message : 'Socket snapshot failed') }
    finally { setLoading(false) }
  }
  async function analyze() {
    setLoading(true)
    try {
      const r = await fetch(API + '/api/analyze', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ event: { process: processName, destination: target, url: target, content, action: 'outbound_request', timestamp: new Date().toISOString() } }) })
      const d = await r.json(); if (!r.ok) throw new Error(d.detail || 'Analysis failed'); await refresh(); setMessage(`Analysis complete: ${d.risk_level.toUpperCase()} risk, score ${d.risk_score}/100.`)
    } catch (e) { setMessage(e instanceof Error ? e.message : 'Analysis failed') }
    finally { setLoading(false) }
  }
  async function uploadFile(file?: File) {
    if (!file) return
    const fd = new FormData(); fd.append('file', file); setLoading(true)
    try { const r = await fetch(API + '/api/upload-json', { method: 'POST', body: fd }); const d = await r.json(); if (!r.ok) throw new Error(d.detail || 'Upload failed'); await refresh(); setMessage(`Analyzed ${d.uploaded} events.`) }
    catch (e) { setMessage(e instanceof Error ? e.message : 'Upload failed') }
    finally { setLoading(false) }
  }
  async function investigate() {
    setLoading(true); setExplanation('')
    try { const r = await fetch(API + '/api/investigate', { method: 'POST' }); const d = await r.json(); setExplanation(d.summary || d.message || 'No explanation returned.') }
    catch { setExplanation('Could not reach backend.') }
    finally { setLoading(false) }
  }
  const providers = rows.reduce<Record<string, number>>((acc, row) => { if (row.provider && row.provider !== 'unknown') acc[row.provider] = (acc[row.provider] || 0) + 1; return acc }, {})
  return <main className="shell">
    <aside className="sidebar"><div className="brand"><div className="brand-icon"><ShieldCheck size={23}/></div><div><strong>SHADOW<span>SENTINEL</span></strong><small>AI SECURITY CONSOLE</small></div></div>
      <div className="nav-label">WORKSPACE</div><div className="nav-item active"><Activity size={17}/> Overview</div><div className="nav-item"><ShieldAlert size={17}/> Risk findings <span className="nav-count">{summary.flagged_events}</span></div><div className="nav-item"><Cpu size={17}/> AI providers</div>
      <div className="side-bottom"><div className="status-dot"/> LOCAL ANALYSIS MODE<small>Event logs stay on this machine.</small></div>
    </aside>
    <section className="content"><header className="topbar"><div><div className="eyebrow">SECURITY / OVERVIEW</div><h1>Shadow IT Intelligence</h1><p>Visibility into AI traffic, exposed data, and agent activity.</p></div><button className="button secondary" onClick={() => void refresh()}><RefreshCw size={15}/> Refresh</button></header>
      {message && <div className="notice">{message}</div>}
      <section className="metrics">
        <Metric icon={<Activity/>} label="Events analyzed" value={summary.total_events} sub="Audited request events"/>
        <Metric icon={<ShieldAlert/>} label="Flagged events" value={summary.flagged_events} sub="Events with findings" alert={summary.flagged_events > 0}/>
        <Metric icon={<Zap/>} label="Critical events" value={summary.critical_events} sub="Immediate review advised" alert={summary.critical_events > 0}/>
        <Metric icon={<Cpu/>} label="AI providers" value={summary.providers} sub="Distinct providers seen"/>
      </section>
      <div className="grid-main">
        <section className="panel"><div className="panel-head"><div><h2>Traffic &amp; findings</h2><p>Latest analyzed events · sanitized output</p></div><span className="pill"><CircleDot size={11}/> LIVE DATA</span></div>
          <div className="table-wrap"><table><thead><tr><th>PROCESS / DESTINATION</th><th>PROVIDER</th><th>RISK</th><th>FINDINGS</th></tr></thead><tbody>
            {rows.length === 0 ? <tr><td colSpan={4} className="empty">No events yet. Load demo events to see the scanner in action.</td></tr> : rows.map((r, i) => <tr key={i}><td><strong>{r.process}</strong><small>{r.destination}</small></td><td><span className="provider">{r.provider}</span></td><td><span className={'risk ' + r.risk_level}>{r.risk_level} · {r.risk_score}</span></td><td>{r.finding_count}</td></tr>)}
          </tbody></table></div><div className="panel-foot">Risk score is a heuristic for triage, not proof of data exfiltration.</div>
        </section>
        <section className="panel provider-panel"><div className="panel-head"><div><h2>Provider activity</h2><p>Detected in submitted events</p></div></div>
          {Object.keys(providers).length === 0 ? <div className="empty compact">No provider activity detected.</div> : Object.entries(providers).sort((a,b)=>b[1]-a[1]).map(([name,count]) => <div className="provider-row" key={name}><span><span className="provider-dot"/> {name}</span><strong>{count}</strong></div>)}
          <div className="divider"/><div className="score-label">AVERAGE RISK SCORE</div><div className="score">{summary.average_risk}<small>/ 100</small></div><div className="score-track"><div style={{width: summary.average_risk + '%'}}/></div>
        </section>
      </div>
      <div className="grid-bottom">
        <section className="panel"><div className="panel-head"><div><h2>Analyze an event</h2><p>Use synthetic test data; secret values are never echoed back.</p></div><Search size={17}/></div>
          <label>Process name<input value={processName} onChange={e=>setProcessName(e.target.value)}/></label><label>Destination / URL<input value={target} onChange={e=>setTarget(e.target.value)}/></label><label>Request text or action<textarea rows={3} value={content} onChange={e=>setContent(e.target.value)}/></label>
          <div className="actions"><button className="button primary" disabled={loading} onClick={() => void analyze()}><Search size={15}/> Analyze event</button><button className="button secondary" disabled={loading} onClick={() => void loadDemo()}><Zap size={15}/> Load demo</button><button className="button secondary" disabled={loading} onClick={() => void socketSnapshot()}><Activity size={15}/> Snapshot socket metadata</button></div><p className="panel-foot">Socket snapshot is opt-in and T1-only. HTTPS prompt bodies are not inspected.</p>
        </section>
        <section className="panel"><div className="panel-head"><div><h2>AI investigation</h2><p>Optional sanitized findings summary via Featherless.</p></div><ExternalLink size={17}/></div>
          <div className="ai-box"><div className="ai-mark">✳</div><div><strong>Remediation assistant</strong><p>Only finding labels, severities, and sanitized evidence are sent. Raw event content is not sent.</p></div></div>
          <button className="button primary full" disabled={loading} onClick={() => void investigate()}>Generate investigation summary</button>
          {explanation && <pre className="explanation">{explanation}</pre>}
          <div className="privacy-note"><ShieldCheck size={15}/> Featherless API key is optional. Without it, local detection still works.</div>
        </section>
      </div>
      <footer>SHADOWLENS AI <span>•</span> HACKATHON MVP <span>•</span> PRIVACY-FIRST BY DESIGN</footer>
    </section>
  </main>
}
function Metric({icon,label,value,sub,alert=false}:{icon:React.ReactNode;label:string;value:number;sub:string;alert?:boolean}) { return <div className="metric"><div className={'metric-icon '+(alert?'danger':'')}>{icon}</div><div><span>{label}</span><strong>{value}</strong><small>{sub}</small></div></div> }
