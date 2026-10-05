import { useMemo, useRef, useState } from 'react'
import type { ChangeEvent, FormEvent } from 'react'
import './App.css'

type Finding = {
  threat_id: string; title: string; cve: string | null; attack_type: string; severity: string
  source: { type: string; url: string; published: string; retrieved_at: string }
  status: string; patch_status: string | null; repository: string; branch: string | null
  affected_files: string[]; affected_lines: number[]; confidence: number
  vulnerability_hypothesis: string; recommended_fix: string; security_test_path: string | null
  code: Record<string, { before: string; after: string | null }>; diff: string | null
  patch_attempts: number; final_audit: string | null; reason: string | null; timestamp: string
}

const sample: Finding = {
  threat_id: 'manual-scan-005-hardcoded-jwt-secret', title: 'Hardcoded JWT Secret', cve: null,
  attack_type: 'hardcoded_secret', severity: 'medium',
  source: { type: 'other', url: 'https://local-scan.invalid/offline-gemma-self-scan', published: '2026-10-05T08:28:20.454907+00:00', retrieved_at: '2026-10-05T08:28:20.454907+00:00' },
  status: 'ai_error', patch_status: null, repository: 'C:\\Users\\Ojas Singh\\Downloads\\test_vulnerability_repo-main', branch: null,
  affected_files: [], affected_lines: [], confidence: 0,
  vulnerability_hypothesis: 'A sensitive cryptographic secret (JWT_SECRET) is hardcoded in the repository. If exposed, an attacker could forge authentication tokens.',
  recommended_fix: 'Remove the hardcoded secret and load the key from a secure environment variable or secrets manager. Rotate the exposed key and invalidate existing tokens.',
  security_test_path: null, code: {}, diff: null, patch_attempts: 0, final_audit: null,
  reason: 'Gemma did not return valid JSON after 2 attempt(s): Expecting value: line 1 column 1 (char 0)',
  timestamp: '2026-10-05T08:28:49.375861+00:00',
}

const readSaved = (): Finding[] => {
  try { const value = localStorage.getItem('sentinelaudit-findings'); return value ? JSON.parse(value) as Finding[] : [sample] } catch { return [sample] }
}
const pretty = (value: string) => value.replaceAll('_', ' ')
const date = (value?: string | null) => value ? new Date(value).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : '—'
const icon = (name: string) => {
  const paths: Record<string, string> = { grid: '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>', shield: '<path d="M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11Z"/><path d="m9 12 2 2 4-4"/>', clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>', upload: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m17 8-5-5-5 5M12 3v12"/>', search: '<circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/>', arrow: '<path d="M7 17 17 7M7 7h10v10"}', close: '<path d="m18 6-12 12M6 6l12 12"/>', file: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6M8 13h8M8 17h8"/>', chevron: '<path d="m9 18 6-6-6-6"/>' }
  return <svg className="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" dangerouslySetInnerHTML={{ __html: paths[name] || paths.file }} />
}

function App() {
  const [findings, setFindings] = useState<Finding[]>(readSaved)
  const [query, setQuery] = useState('')
  const [severity, setSeverity] = useState('all')
  const [status, setStatus] = useState('all')
  const [active, setActive] = useState<Finding | null>(null)
  const [section, setSection] = useState<'overview' | 'findings' | 'history'>('overview')
  const [notice, setNotice] = useState('')
  const [repoUrl, setRepoUrl] = useState('')
  const [repoBusy, setRepoBusy] = useState(false)
  const [repoError, setRepoError] = useState('')
  const fileRef = useRef<HTMLInputElement>(null)
  const save = (items: Finding[]) => { setFindings(items); localStorage.setItem('sentinelaudit-findings', JSON.stringify(items)) }
  const filtered = useMemo(() => findings.filter(f => (severity === 'all' || f.severity.toLowerCase() === severity) && (status === 'all' || f.status === status) && `${f.title} ${f.threat_id} ${f.attack_type} ${f.repository}`.toLowerCase().includes(query.toLowerCase())), [findings, query, severity, status])
  const patches = findings.filter(f => f.patch_status)
  const repositoriesCount = new Set(findings.map(f => f.repository).filter(Boolean)).size
  const analyzedCount = findings.filter(f => f.status !== 'ai_error').length
  const patchAttemptsCount = findings.reduce((total, f) => total + (f.patch_attempts || 0), 0)
  const auditedCount = findings.filter(f => f.final_audit).length
  const severityData = ['critical', 'high', 'medium', 'low'].map(name => ({ name, count: findings.filter(f => f.severity.toLowerCase() === name).length }))
  const reviewData = ['confirmed', 'not_applicable', 'uncertain', 'ai_error', 'guard_rejected'].map(name => ({ name, count: findings.filter(f => f.status === name).length }))
  const patchData = [{ name: 'Fixed', count: findings.filter(f => f.patch_status === 'fixed').length }, { name: 'Unresolved', count: findings.filter(f => f.patch_status === 'unresolved').length }, { name: 'Not attempted', count: findings.filter(f => !f.patch_status).length }]
  const maxFor = (data: { count: number }[]) => Math.max(1, ...data.map(item => item.count))
  const validDates = findings.map(f => new Date(f.timestamp)).filter(d => !Number.isNaN(d.getTime()))
  const activityEnd = validDates.length ? new Date(Math.max(...validDates.map(d => d.getTime()))) : new Date()
  activityEnd.setHours(0, 0, 0, 0)
  const activityDays = Array.from({ length: 7 }, (_, i) => {
    const day = new Date(activityEnd); day.setDate(day.getDate() - (6 - i))
    const count = validDates.filter(d => d.getFullYear() === day.getFullYear() && d.getMonth() === day.getMonth() && d.getDate() === day.getDate()).length
    return { day, count }
  })
  const maxActivity = maxFor(activityDays)
  const linePoints = activityDays.map((item, i) => ({ x: 42 + i * 48, y: 124 - (item.count / maxActivity) * 92 }))
  const linePath = linePoints.map((point, i) => `${i === 0 ? 'M' : 'L'} ${point.x} ${point.y}`).join(' ')
  const importFile = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]; if (!file) return
    try {
      const parsed: unknown = JSON.parse(await file.text()); const values = Array.isArray(parsed) ? parsed : [parsed]
      if (!values.length || !values.every(v => typeof v === 'object' && v !== null && 'threat_id' in v && 'title' in v)) throw new Error('Expected a finding object or array with threat_id and title fields.')
      const incoming = values as Finding[]; const merged = [...findings]
      incoming.forEach(item => { const index = merged.findIndex(existing => existing.threat_id === item.threat_id); if (index >= 0) merged[index] = item; else merged.unshift(item) })
      save(merged); setNotice(`${incoming.length} finding${incoming.length === 1 ? '' : 's'} imported`); setTimeout(() => setNotice(''), 3000)
    } catch (error) { setNotice(error instanceof Error ? error.message : 'Could not read JSON file'); setTimeout(() => setNotice(''), 4000) }
    event.target.value = ''
  }
  const exportData = () => { const blob = new Blob([JSON.stringify(findings, null, 2)], { type: 'application/json' }); const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = 'sentinelaudit-findings.json'; a.click(); URL.revokeObjectURL(url) }
  const submitRepository = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); setRepoError('')
    let parsedUrl: URL
    try { parsedUrl = new URL(repoUrl.trim()) } catch { setRepoError('Enter a valid GitHub repository URL.'); return }
    if (parsedUrl.hostname !== 'github.com' || parsedUrl.pathname.split('/').filter(Boolean).length < 2) { setRepoError('Use a GitHub URL in the format github.com/owner/repository.'); return }
    setRepoBusy(true)
    try {
      const endpoint = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/scan'
      const response = await fetch(endpoint, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ repository_url: parsedUrl.href.replace(/\/$/, '') }) })
      const body: unknown = await response.json().catch(() => null)
      if (!response.ok) throw new Error(typeof body === 'object' && body !== null && 'detail' in body ? String(body.detail) : `Backend returned ${response.status}.`)
      const payload = typeof body === 'object' && body !== null && 'findings' in body ? body.findings : body
      const values = Array.isArray(payload) ? payload : [payload]
      const valid = values.filter((v): v is Finding => typeof v === 'object' && v !== null && 'threat_id' in v && 'title' in v)
      if (valid.length) {
        const merged = [...findings]
        valid.forEach(item => { const index = merged.findIndex(existing => existing.threat_id === item.threat_id); if (index >= 0) merged[index] = item; else merged.unshift(item) })
        save(merged); setNotice(`${valid.length} finding${valid.length === 1 ? '' : 's'} received from the repository scan`); setTimeout(() => setNotice(''), 4000)
      } else setNotice('Repository submitted to the backend. Findings will appear after a scan result is returned.')
    } catch (error) { setRepoError(error instanceof Error ? `${error.message} Check that the backend is running and VITE_API_URL points to its scan endpoint.` : 'Could not reach the scan backend.') }
    finally { setRepoBusy(false) }
  }

  return <div className="app-shell">
    <aside className="sidebar">
      <a className="brand" href="#overview" onClick={() => setSection('overview')}><span className="brand-mark">{icon('shield')}</span><span>sentinel<span className="brand-light">audit</span><small>SECURITY WORKSPACE</small></span></a>
      <div className="workspace-label">WORKSPACE</div>
      <nav className="nav-list" aria-label="Main navigation">
        {([['overview', 'grid', 'Overview'], ['findings', 'shield', 'Vulnerabilities'], ['history', 'clock', 'Patch history']] as const).map(([key, glyph, label]) => <button className={`nav-item ${section === key ? 'selected' : ''}`} key={key} onClick={() => setSection(key)}>{icon(glyph)}<span>{label}</span>{key === 'findings' && <b className="nav-count">{findings.length}</b>}</button>)}
      </nav>
      <div className="sidebar-bottom"><div className="connection-dot" /><span>Local workspace</span><span className="connection-state">Connected</span><p>Findings stay in this browser. Import a scan to get started.</p></div>
    </aside>

    <main className="main-content">
      <header className="topbar"><div className="breadcrumb">Security <span>/</span> <strong>{section === 'overview' ? 'Overview' : section === 'findings' ? 'Vulnerabilities' : 'Patch history'}</strong></div><div className="top-actions"><span className="updated"><span className="live-dot" /> Updated just now</span><button className="button button-outline" onClick={exportData}>Export data</button><button className="button button-primary" onClick={() => fileRef.current?.click()}>{icon('upload')} Import scan</button><input ref={fileRef} type="file" accept="application/json,.json" hidden onChange={importFile} /></div></header>

      <div className="page-wrap">
        <section className="page-heading"><div><div className="eyebrow">SECURITY WORKSPACE <span>·</span> {new Date().toLocaleDateString(undefined, { month: 'long', year: 'numeric' }).toUpperCase()}</div><h1>{section === 'history' ? 'Patch history' : section === 'findings' ? 'Vulnerabilities' : 'Security overview'}</h1><p>{section === 'history' ? 'Review remediation attempts and audit outcomes across your repositories.' : section === 'findings' ? 'Search, filter, and inspect every vulnerability found in your repositories.' : 'Monitor findings, agent progress, and remediation health in one place.'}</p></div><button className="button button-primary heading-import" onClick={() => fileRef.current?.click()}>{icon('upload')} Import scan</button></section>
        {notice && <div className="notice" role="status">{notice}</div>}

        {section !== 'history' && <>
        {section === 'overview' && <>
          <section className="metrics" aria-label="Finding summary">
            <article className="metric-card"><div className="metric-top"><span>Total findings</span><span className="metric-icon violet">{icon('shield')}</span></div><div className="metric-value">{findings.length.toString().padStart(2, '0')}</div><div className="metric-note">Across all imported scans</div></article>
            <article className="metric-card"><div className="metric-top"><span>Need review</span><span className="metric-icon amber">!</span></div><div className="metric-value">{findings.filter(f => ['ai_error', 'uncertain', 'guard_rejected'].includes(f.status)).length.toString().padStart(2, '0')}</div><div className="metric-note">Require security team attention</div></article>
            <article className="metric-card"><div className="metric-top"><span>Patch success</span><span className="metric-icon green">✓</span></div><div className="metric-value">{patches.length ? `${Math.round(patches.filter(f => f.patch_status === 'fixed').length / patches.length * 100)}%` : '—'}</div><div className="metric-note">{patches.length ? `${patches.filter(f => f.patch_status === 'fixed').length} of ${patches.length} attempts fixed` : 'No patch attempts yet'}</div></article>
            <article className="metric-card"><div className="metric-top"><span>Repositories</span><span className="metric-icon blue">{icon('grid')}</span></div><div className="metric-value">{new Set(findings.map(f => f.repository).filter(Boolean)).size.toString().padStart(2, '0')}</div><div className="metric-note">With imported findings</div></article>
          </section>
          <section className="content-card workflow-card" aria-label="Security agent workflow">
            <div className="workflow-heading"><div><span className="eyebrow">AGENT WORKFLOW</span><h2>Repository security pipeline</h2><p>Follow each repository from discovery through remediation and final audit.</p></div><span className="workflow-live"><i /> Live status</span></div>
            <div className="workflow-track">
              <div className={`workflow-node ${repositoriesCount ? 'node-ready' : ''}`}><span className="node-number">01</span><span className="node-name">Repository</span><strong>{repositoriesCount} <small>connected</small></strong><span className="node-note">Source intake</span></div><span className={`workflow-connector ${repositoriesCount ? 'connector-ready' : ''}`} />
              <div className={`workflow-node ${analyzedCount ? 'node-ready' : findings.length ? 'node-attention' : ''}`}><span className="node-number">02</span><span className="node-name">Reverse engineer</span><strong>{analyzedCount} <small>analyzed</small></strong><span className="node-note">Code understanding</span></div><span className={`workflow-connector ${analyzedCount ? 'connector-ready' : ''}`} />
              <div className={`workflow-node ${findings.length ? 'node-ready' : ''}`}><span className="node-number">03</span><span className="node-name">Triage findings</span><strong>{findings.length} <small>classified</small></strong><span className="node-note">Severity &amp; source</span></div><span className={`workflow-connector ${patchAttemptsCount ? 'connector-ready' : ''}`} />
              <div className={`workflow-node ${patchAttemptsCount ? 'node-ready' : ''}`}><span className="node-number">04</span><span className="node-name">Patch agent</span><strong>{patchAttemptsCount} <small>attempts</small></strong><span className="node-note">Fix &amp; test</span></div><span className={`workflow-connector ${auditedCount ? 'connector-ready' : ''}`} />
              <div className={`workflow-node ${auditedCount ? 'node-ready' : ''}`}><span className="node-number">05</span><span className="node-name">Final audit</span><strong>{auditedCount} <small>verified</small></strong><span className="node-note">Outcome review</span></div>
            </div>
            {findings.some(f => f.status === 'ai_error') && <div className="workflow-callout"><span>!</span><p><strong>Analysis needs attention.</strong> {findings.filter(f => f.status === 'ai_error').length} finding(s) returned an AI error before reverse engineering completed.</p><button onClick={() => setSection('findings')}>Review findings <span>→</span></button></div>}
          </section>
          <section className="charts-grid" aria-label="Finding analysis charts">
            <article className="content-card chart-card line-chart-card">
              <div className="chart-heading"><div><h2>Finding activity</h2><p>Daily findings in the latest 7-day window</p></div><span className="chart-total">{findings.length} total</span></div>
              <div className="line-chart-wrap"><svg className="line-chart" viewBox="0 0 360 174" role="img" aria-label="Line graph of daily finding counts over seven days">
                {[0, 1, 2, 3].map(tick => { const value = Math.ceil(maxActivity * (3 - tick) / 3); const y = 25 + tick * 33; return <g key={tick}><line x1="37" y1={y} x2="340" y2={y} className="chart-gridline"/><text x="27" y={y + 4} textAnchor="end" className="axis-label">{value}</text></g> })}
                <path d={`${linePath} L 330 142 L 42 142 Z`} className="line-chart-area"/><path d={linePath} className="line-chart-path"/>
                {linePoints.map((point, i) => <g key={i}><circle cx={point.x} cy={point.y} r="4" className="line-chart-point"><title>{activityDays[i].count} findings on {activityDays[i].day.toLocaleDateString()}</title></circle><text x={point.x} y="161" textAnchor="middle" className="axis-label">{activityDays[i].day.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}</text></g>)}
              </svg></div>
              <div className="chart-foot">7 days ending {activityEnd.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })}. Window follows the latest finding date.</div>
            </article>
            <article className="content-card chart-card histogram-card">
              <div className="chart-heading"><div><h2>Severity histogram</h2><p>Finding count by severity</p></div><span className="chart-total">{findings.length} total</span></div>
              <div className="histogram-wrap"><svg className="histogram" viewBox="0 0 360 174" role="img" aria-label="Histogram of findings by severity">
                {[0, 1, 2, 3].map(tick => { const value = Math.ceil(maxFor(severityData) * (3 - tick) / 3); const y = 25 + tick * 33; return <g key={tick}><line x1="37" y1={y} x2="340" y2={y} className="chart-gridline"/><text x="27" y={y + 4} textAnchor="end" className="axis-label">{value}</text></g> })}
                {severityData.map((item, i) => { const height = item.count ? Math.max(3, item.count / maxFor(severityData) * 98) : 0; const x = 67 + i * 72; const y = 142 - height; return <g key={item.name}><rect x={x} y={y} width="36" height={height} rx="5" className={`histogram-bar bar-${item.name}`}><title>{item.count} {item.name} findings</title></rect><text x={x + 18} y="161" textAnchor="middle" className="axis-label axis-category">{item.name}</text><text x={x + 18} y={y - 7} textAnchor="middle" className="bar-value">{item.count}</text></g> })}
              </svg></div>
              <div className="chart-foot">Severity is Gemma’s estimate recorded in each finding.</div>
            </article>
            <article className="content-card chart-card outcome-chart-card">
              <div className="chart-heading"><div><h2>Analysis & patch outcomes</h2><p>Disposition across imported findings</p></div><span className="chart-total">{findings.length} total</span></div>
              <div className="outcome-columns"><div><h3>AI review</h3>{reviewData.map(item => <div className="outcome-row" key={item.name}><span className={`outcome-dot dot-${item.name}`} /><span>{pretty(item.name)}</span><strong>{item.count}</strong></div>)}</div><div><h3>Patch status</h3>{patchData.map(item => <div className="outcome-row" key={item.name}><span className={`outcome-dot dot-patch-${item.name.toLowerCase().replace(' ', '-')}`} /><span>{item.name}</span><strong>{item.count}</strong></div>)}</div></div>
              <div className="chart-foot">Patch success rate: {patches.length ? `${Math.round(patches.filter(f => f.patch_status === 'fixed').length / patches.length * 100)}%` : 'No attempts yet'}</div>
            </article>
          </section>
          <section className="content-card repo-submit-card"><div className="repo-submit-copy"><span className="repo-submit-icon">{icon('arrow')}</span><div><h2>Scan a GitHub repository</h2><p>Paste a public repository URL to send it to your security scanning backend.</p></div></div><form className="repo-submit-form" onSubmit={submitRepository}><label className="repo-input-wrap"><span className="github-mark">GH</span><input type="url" value={repoUrl} onChange={e => setRepoUrl(e.target.value)} placeholder="https://github.com/owner/repository" aria-label="GitHub repository URL" required /></label><button className="button button-primary" disabled={repoBusy}>{repoBusy ? <><span className="spinner" /> Submitting…</> : 'Send to scanner'}</button></form>{repoError && <p className="repo-error" role="alert">{repoError}</p>}<div className="endpoint-note">Backend endpoint: <code>{import.meta.env.VITE_API_URL || 'http://localhost:8000/api/scan'}</code><span>·</span> Set <code>VITE_API_URL</code> to change it</div></section>
          </>}
          {section === 'findings' && <>
          <section className="findings-summary"><div><span>All findings</span><strong>{findings.length}</strong></div><div><span>Needs review</span><strong>{findings.filter(f => ['ai_error', 'uncertain', 'guard_rejected'].includes(f.status)).length}</strong></div><div><span>Patch attempts</span><strong>{patchAttemptsCount}</strong></div><div><span>Successfully patched</span><strong>{findings.filter(f => f.patch_status === 'fixed').length}</strong></div></section>
          <section className="content-card findings-card">
            <div className="card-heading"><div><h2>All vulnerabilities</h2><p>Filter and inspect imported security findings</p></div></div>
            <div className="filters"><label className="search-box">{icon('search')}<input value={query} onChange={e => setQuery(e.target.value)} placeholder="Search findings, IDs, repositories..." /></label><select aria-label="Filter severity" value={severity} onChange={e => setSeverity(e.target.value)}><option value="all">All severities</option>{['critical', 'high', 'medium', 'low'].map(v => <option key={v} value={v}>{v[0].toUpperCase() + v.slice(1)}</option>)}</select><select aria-label="Filter status" value={status} onChange={e => setStatus(e.target.value)}><option value="all">All statuses</option>{['confirmed', 'not_applicable', 'uncertain', 'ai_error', 'guard_rejected'].map(v => <option key={v} value={v}>{pretty(v)}</option>)}</select></div>
            <div className="table-wrap"><table><thead><tr><th>VULNERABILITY</th><th>SEVERITY</th><th>AI REVIEW</th><th>PATCH STATUS</th><th>REPOSITORY</th><th>LAST DETECTED</th><th /></tr></thead><tbody>{filtered.map(f => <tr key={f.threat_id} onClick={() => setActive(f)} tabIndex={0} onKeyDown={e => e.key === 'Enter' && setActive(f)}><td><div className="finding-title">{f.title}</div><div className="finding-id">{f.cve || f.threat_id}</div></td><td><span className={`severity severity-${f.severity.toLowerCase()}`}><i />{pretty(f.severity)}</span></td><td><span className={`status status-${f.status}`}>{pretty(f.status)}</span></td><td>{f.patch_status ? <span className={`status status-${f.patch_status}`}>{pretty(f.patch_status)}</span> : <span className="muted">Not attempted</span>}</td><td><span className="repo-name">{f.repository.split(/[\\/]/).filter(Boolean).pop() || 'Unknown repository'}</span></td><td className="date-cell">{date(f.timestamp)}</td><td>{icon('chevron')}</td></tr>)}</tbody></table>{filtered.length === 0 && <div className="empty-state">{findings.length ? 'No findings match these filters.' : 'No findings yet. Import a JSON scan to get started.'}</div>}</div>
            <div className="table-footer">Showing <strong>{filtered.length}</strong> of <strong>{findings.length}</strong> findings<span>Data stored locally in this browser</span></div>
          </section>
          </>}
          {section === 'overview' && <div className="bottom-grid"><section className="content-card source-card"><div className="card-heading"><div><h2>Latest scan</h2><p>Most recently imported finding</p></div><span className="scan-icon">{icon('file')}</span></div>{findings[0] ? <><div className="scan-title">{findings[0].title}</div><div className="scan-meta"><span className="live-dot" />{date(findings[0].timestamp)}</div><div className="source-url"><span>Source</span><a href={findings[0].source.url} target="_blank" rel="noreferrer">{findings[0].source.url}{icon('arrow')}</a></div><div className="scan-footer"><span>Finding ID</span><code>{findings[0].threat_id}</code></div></> : <div className="empty-mini">Import a scan to see its source details.</div>}</section>
            <section className="content-card activity-card"><div className="card-heading"><div><h2>Remediation activity</h2><p>Recent patch outcomes</p></div><button className="text-button" onClick={() => setSection('history')}>History <span>→</span></button></div>{patches.length ? <div className="activity-list">{patches.slice(0, 3).map(f => <button key={f.threat_id} className="activity-row" onClick={() => setActive(f)}><span className={`activity-mark ${f.patch_status}`}>{f.patch_status === 'fixed' ? '✓' : '!'}</span><span className="activity-copy"><strong>{f.title}</strong><small>{f.branch || f.threat_id}</small></span><span className={`status status-${f.patch_status}`}>{pretty(f.patch_status || '')}</span></button>)}</div> : <div className="activity-empty"><span className="empty-clock">{icon('clock')}</span><span><strong>No patch history yet</strong><small>Patch attempts and final audit results will appear here.</small></span></div>}</section></div>}
        </>}
        {section === 'history' && <section className="content-card history-card"><div className="card-heading"><div><h2>Remediation attempts</h2><p>Patch status and final audit from imported scan results</p></div></div>{patches.length ? <div className="history-list">{patches.map(f => <button className="history-row" key={f.threat_id} onClick={() => setActive(f)}><span className={`activity-mark ${f.patch_status}`}>{f.patch_status === 'fixed' ? '✓' : '!'}</span><span><strong>{f.title}</strong><small>{f.branch || f.threat_id} · {f.patch_attempts} attempt{f.patch_attempts === 1 ? '' : 's'}</small></span><span className="history-audit">Audit: {f.final_audit ? pretty(f.final_audit) : 'Pending'}</span><span className={`status status-${f.patch_status}`}>{pretty(f.patch_status || '')}</span></button>)}</div> : <div className="empty-state history-empty">No previous patches found. When a scan includes a patch attempt, its branch, diff, attempts, and final audit will be recorded here.</div>}</section>}
        <footer className="page-footer"><span>SentinelAudit <span>·</span> Security findings workspace</span><span>Local data <i /> All changes saved</span></footer>
      </div>
    </main>

    {active && <div className="modal-backdrop" onMouseDown={e => e.target === e.currentTarget && setActive(null)}><aside className="detail-panel" role="dialog" aria-modal="true" aria-label={`Finding details: ${active.title}`}><div className="detail-header"><div><div className="eyebrow">VULNERABILITY DETAIL</div><h2>{active.title}</h2></div><button className="icon-button" aria-label="Close details" onClick={() => setActive(null)}>{icon('close')}</button></div><div className="detail-scroll"><div className="detail-badges"><span className={`severity severity-${active.severity.toLowerCase()}`}><i />{pretty(active.severity)}</span><span className={`status status-${active.status}`}>{pretty(active.status)}</span></div><div className="detail-id">{active.threat_id}</div><section className="detail-section"><h3>Finding overview</h3><dl><div><dt>Attack type</dt><dd>{pretty(active.attack_type)}</dd></div><div><dt>CVE</dt><dd>{active.cve || 'Not assigned'}</dd></div><div><dt>Confidence</dt><dd>{Math.round(active.confidence * 100)}%</dd></div><div><dt>Repository</dt><dd className="wrap-value">{active.repository || '—'}</dd></div><div><dt>Detected</dt><dd>{date(active.timestamp)}</dd></div></dl></section><section className="detail-section"><h3>Source</h3><dl><div><dt>Type</dt><dd>{pretty(active.source?.type || 'unknown')}</dd></div><div><dt>Published</dt><dd>{date(active.source?.published)}</dd></div><div><dt>Retrieved</dt><dd>{date(active.source?.retrieved_at)}</dd></div></dl><a className="detail-link" href={active.source?.url} target="_blank" rel="noreferrer">{active.source?.url || 'No source URL'} {icon('arrow')}</a></section><section className="detail-section"><h3>Reverse engineering</h3><p className="detail-paragraph">{active.vulnerability_hypothesis || 'No hypothesis provided.'}</p>{active.reason && <div className="reason-box"><strong>Review note</strong><p>{active.reason}</p></div>}<div className="recommendation"><strong>Recommended fix</strong><p>{active.recommended_fix || 'No recommendation provided.'}</p></div></section><section className="detail-section"><h3>Affected areas</h3>{active.affected_files?.length ? <ul className="file-list">{active.affected_files.map((file, i) => <li key={file}>{icon('file')}<span>{file}</span>{active.affected_lines?.[i] && <code>:{active.affected_lines[i]}</code>}</li>)}</ul> : <p className="muted detail-paragraph">No affected files or lines were reported.</p>}{active.security_test_path && <div className="test-path">Security test <code>{active.security_test_path}</code></div>}</section><section className="detail-section"><h3>Patching result</h3><dl><div><dt>Status</dt><dd>{active.patch_status ? pretty(active.patch_status) : 'Not attempted'}</dd></div><div><dt>Attempts</dt><dd>{active.patch_attempts}</dd></div><div><dt>Branch</dt><dd className="wrap-value">{active.branch || '—'}</dd></div><div><dt>Final audit</dt><dd>{active.final_audit ? pretty(active.final_audit) : '—'}</dd></div></dl>{active.diff ? <pre className="diff-block">{active.diff}</pre> : <p className="muted detail-paragraph">No patch diff available.</p>}{Object.entries(active.code || {}).map(([path, value]) => <div className="code-change" key={path}><strong>{path}</strong><pre>{value.before}{value.after ? `\n\nAfter:\n${value.after}` : ''}</pre></div>)}</section></div></aside></div>}
  </div>
}

export default App
