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
        <section className="page-heading"><div><div className="eyebrow">SECURITY POSTURE <span>·</span> OCTOBER 2026</div><h1>{section === 'history' ? 'Patch history' : section === 'findings' ? 'Vulnerabilities' : 'Security overview'}</h1><p>{section === 'history' ? 'Review remediation attempts and audit outcomes across your repositories.' : 'A clear view of findings, remediation progress, and repository risk.'}</p></div><button className="button button-primary heading-import" onClick={() => fileRef.current?.click()}>{icon('upload')} Import scan</button></section>
        {notice && <div className="notice" role="status">{notice}</div>}

        {section !== 'history' && <section className="content-card repo-submit-card"><div className="repo-submit-copy"><span className="repo-submit-icon">{icon('arrow')}</span><div><h2>Scan a GitHub repository</h2><p>Paste a public repository URL to send it to your security scanning backend.</p></div></div><form className="repo-submit-form" onSubmit={submitRepository}><label className="repo-input-wrap"><span className="github-mark">GH</span><input type="url" value={repoUrl} onChange={e => setRepoUrl(e.target.value)} placeholder="https://github.com/owner/repository" aria-label="GitHub repository URL" required /></label><button className="button button-primary" disabled={repoBusy}>{repoBusy ? <><span className="spinner" /> Submitting…</> : 'Send to scanner'}</button></form>{repoError && <p className="repo-error" role="alert">{repoError}</p>}<div className="endpoint-note">Backend endpoint: <code>{import.meta.env.VITE_API_URL || 'http://localhost:8000/api/scan'}</code><span>·</span> Set <code>VITE_API_URL</code> to change it</div></section>}

        {section !== 'history' && <>
          <section className="metrics" aria-label="Finding summary">
            <article className="metric-card"><div className="metric-top"><span>Total findings</span><span className="metric-icon violet">{icon('shield')}</span></div><div className="metric-value">{findings.length.toString().padStart(2, '0')}</div><div className="metric-note">Across all imported scans</div></article>
            <article className="metric-card"><div className="metric-top"><span>Need review</span><span className="metric-icon amber">!</span></div><div className="metric-value">{findings.filter(f => ['ai_error', 'uncertain', 'guard_rejected'].includes(f.status)).length.toString().padStart(2, '0')}</div><div className="metric-note">Require security team attention</div></article>
            <article className="metric-card"><div className="metric-top"><span>Patch success</span><span className="metric-icon green">✓</span></div><div className="metric-value">{patches.length ? `${Math.round(patches.filter(f => f.patch_status === 'fixed').length / patches.length * 100)}%` : '—'}</div><div className="metric-note">{patches.length ? `${patches.filter(f => f.patch_status === 'fixed').length} of ${patches.length} attempts fixed` : 'No patch attempts yet'}</div></article>
            <article className="metric-card"><div className="metric-top"><span>Repositories</span><span className="metric-icon blue">{icon('grid')}</span></div><div className="metric-value">{new Set(findings.map(f => f.repository).filter(Boolean)).size.toString().padStart(2, '0')}</div><div className="metric-note">With imported findings</div></article>
          </section>
          <section className="content-card findings-card">
            <div className="card-heading"><div><h2>Recent findings</h2><p>Vulnerabilities detected across your repositories</p></div><button className="text-button" onClick={() => setSection('findings')}>View all <span>→</span></button></div>
            <div className="filters"><label className="search-box">{icon('search')}<input value={query} onChange={e => setQuery(e.target.value)} placeholder="Search findings, IDs, repositories..." /></label><select aria-label="Filter severity" value={severity} onChange={e => setSeverity(e.target.value)}><option value="all">All severities</option>{['critical', 'high', 'medium', 'low'].map(v => <option key={v} value={v}>{v[0].toUpperCase() + v.slice(1)}</option>)}</select><select aria-label="Filter status" value={status} onChange={e => setStatus(e.target.value)}><option value="all">All statuses</option>{['confirmed', 'not_applicable', 'uncertain', 'ai_error', 'guard_rejected'].map(v => <option key={v} value={v}>{pretty(v)}</option>)}</select></div>
            <div className="table-wrap"><table><thead><tr><th>VULNERABILITY</th><th>SEVERITY</th><th>AI REVIEW</th><th>PATCH STATUS</th><th>REPOSITORY</th><th>LAST DETECTED</th><th /></tr></thead><tbody>{filtered.map(f => <tr key={f.threat_id} onClick={() => setActive(f)} tabIndex={0} onKeyDown={e => e.key === 'Enter' && setActive(f)}><td><div className="finding-title">{f.title}</div><div className="finding-id">{f.cve || f.threat_id}</div></td><td><span className={`severity severity-${f.severity.toLowerCase()}`}><i />{pretty(f.severity)}</span></td><td><span className={`status status-${f.status}`}>{pretty(f.status)}</span></td><td>{f.patch_status ? <span className={`status status-${f.patch_status}`}>{pretty(f.patch_status)}</span> : <span className="muted">Not attempted</span>}</td><td><span className="repo-name">{f.repository.split(/[\\/]/).filter(Boolean).pop() || 'Unknown repository'}</span></td><td className="date-cell">{date(f.timestamp)}</td><td>{icon('chevron')}</td></tr>)}</tbody></table>{filtered.length === 0 && <div className="empty-state">{findings.length ? 'No findings match these filters.' : 'No findings yet. Import a JSON scan to get started.'}</div>}</div>
            <div className="table-footer">Showing <strong>{filtered.length}</strong> of <strong>{findings.length}</strong> findings<span>Data stored locally in this browser</span></div>
          </section>
          <div className="bottom-grid"><section className="content-card source-card"><div className="card-heading"><div><h2>Latest scan</h2><p>Most recently imported finding</p></div><span className="scan-icon">{icon('file')}</span></div>{findings[0] ? <><div className="scan-title">{findings[0].title}</div><div className="scan-meta"><span className="live-dot" />{date(findings[0].timestamp)}</div><div className="source-url"><span>Source</span><a href={findings[0].source.url} target="_blank" rel="noreferrer">{findings[0].source.url}{icon('arrow')}</a></div><div className="scan-footer"><span>Finding ID</span><code>{findings[0].threat_id}</code></div></> : <div className="empty-mini">Import a scan to see its source details.</div>}</section>
            <section className="content-card activity-card"><div className="card-heading"><div><h2>Remediation activity</h2><p>Recent patch outcomes</p></div><button className="text-button" onClick={() => setSection('history')}>History <span>→</span></button></div>{patches.length ? <div className="activity-list">{patches.slice(0, 3).map(f => <button key={f.threat_id} className="activity-row" onClick={() => setActive(f)}><span className={`activity-mark ${f.patch_status}`}>{f.patch_status === 'fixed' ? '✓' : '!'}</span><span className="activity-copy"><strong>{f.title}</strong><small>{f.branch || f.threat_id}</small></span><span className={`status status-${f.patch_status}`}>{pretty(f.patch_status || '')}</span></button>)}</div> : <div className="activity-empty"><span className="empty-clock">{icon('clock')}</span><span><strong>No patch history yet</strong><small>Patch attempts and final audit results will appear here.</small></span></div>}</section></div>
        </>}
        {section === 'history' && <section className="content-card history-card"><div className="card-heading"><div><h2>Remediation attempts</h2><p>Patch status and final audit from imported scan results</p></div></div>{patches.length ? <div className="history-list">{patches.map(f => <button className="history-row" key={f.threat_id} onClick={() => setActive(f)}><span className={`activity-mark ${f.patch_status}`}>{f.patch_status === 'fixed' ? '✓' : '!'}</span><span><strong>{f.title}</strong><small>{f.branch || f.threat_id} · {f.patch_attempts} attempt{f.patch_attempts === 1 ? '' : 's'}</small></span><span className="history-audit">Audit: {f.final_audit ? pretty(f.final_audit) : 'Pending'}</span><span className={`status status-${f.patch_status}`}>{pretty(f.patch_status || '')}</span></button>)}</div> : <div className="empty-state history-empty">No previous patches found. When a scan includes a patch attempt, its branch, diff, attempts, and final audit will be recorded here.</div>}</section>}
        <footer className="page-footer"><span>SentinelAudit <span>·</span> Security findings workspace</span><span>Local data <i /> All changes saved</span></footer>
      </div>
    </main>

    {active && <div className="modal-backdrop" onMouseDown={e => e.target === e.currentTarget && setActive(null)}><aside className="detail-panel" role="dialog" aria-modal="true" aria-label={`Finding details: ${active.title}`}><div className="detail-header"><div><div className="eyebrow">VULNERABILITY DETAIL</div><h2>{active.title}</h2></div><button className="icon-button" aria-label="Close details" onClick={() => setActive(null)}>{icon('close')}</button></div><div className="detail-scroll"><div className="detail-badges"><span className={`severity severity-${active.severity.toLowerCase()}`}><i />{pretty(active.severity)}</span><span className={`status status-${active.status}`}>{pretty(active.status)}</span></div><div className="detail-id">{active.threat_id}</div><section className="detail-section"><h3>Finding overview</h3><dl><div><dt>Attack type</dt><dd>{pretty(active.attack_type)}</dd></div><div><dt>CVE</dt><dd>{active.cve || 'Not assigned'}</dd></div><div><dt>Confidence</dt><dd>{Math.round(active.confidence * 100)}%</dd></div><div><dt>Repository</dt><dd className="wrap-value">{active.repository || '—'}</dd></div><div><dt>Detected</dt><dd>{date(active.timestamp)}</dd></div></dl></section><section className="detail-section"><h3>Source</h3><dl><div><dt>Type</dt><dd>{pretty(active.source?.type || 'unknown')}</dd></div><div><dt>Published</dt><dd>{date(active.source?.published)}</dd></div><div><dt>Retrieved</dt><dd>{date(active.source?.retrieved_at)}</dd></div></dl><a className="detail-link" href={active.source?.url} target="_blank" rel="noreferrer">{active.source?.url || 'No source URL'} {icon('arrow')}</a></section><section className="detail-section"><h3>Reverse engineering</h3><p className="detail-paragraph">{active.vulnerability_hypothesis || 'No hypothesis provided.'}</p>{active.reason && <div className="reason-box"><strong>Review note</strong><p>{active.reason}</p></div>}<div className="recommendation"><strong>Recommended fix</strong><p>{active.recommended_fix || 'No recommendation provided.'}</p></div></section><section className="detail-section"><h3>Affected areas</h3>{active.affected_files?.length ? <ul className="file-list">{active.affected_files.map((file, i) => <li key={file}>{icon('file')}<span>{file}</span>{active.affected_lines?.[i] && <code>:{active.affected_lines[i]}</code>}</li>)}</ul> : <p className="muted detail-paragraph">No affected files or lines were reported.</p>}{active.security_test_path && <div className="test-path">Security test <code>{active.security_test_path}</code></div>}</section><section className="detail-section"><h3>Patching result</h3><dl><div><dt>Status</dt><dd>{active.patch_status ? pretty(active.patch_status) : 'Not attempted'}</dd></div><div><dt>Attempts</dt><dd>{active.patch_attempts}</dd></div><div><dt>Branch</dt><dd className="wrap-value">{active.branch || '—'}</dd></div><div><dt>Final audit</dt><dd>{active.final_audit ? pretty(active.final_audit) : '—'}</dd></div></dl>{active.diff ? <pre className="diff-block">{active.diff}</pre> : <p className="muted detail-paragraph">No patch diff available.</p>}{Object.entries(active.code || {}).map(([path, value]) => <div className="code-change" key={path}><strong>{path}</strong><pre>{value.before}{value.after ? `\n\nAfter:\n${value.after}` : ''}</pre></div>)}</section></div></aside></div>}
  </div>
}

export default App
