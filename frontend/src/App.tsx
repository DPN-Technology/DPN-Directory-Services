import { useCallback, useEffect, useMemo, useState } from 'react'
import type { ComponentType, SVGProps } from 'react'
import {
  Activity, ArrowRight, ArrowUpRight, Blocks, CheckCircle2, ChevronRight,
  CircleAlert, Database, Eye, Fingerprint, HardDrive, KeyRound,
  Layers3, LockKeyhole, LogOut, Monitor, RefreshCw, Search,
  Server, Shield, ShieldCheck, Terminal, Users, Wifi, Network,
} from 'lucide-react'

type IconType = ComponentType<SVGProps<SVGSVGElement> & { size?: string | number; strokeWidth?: number }>
type Tab = 'overview' | 'users' | 'groups' | 'devices' | 'diagnostics' | 'verification' | 'about'
type DataTab = 'users' | 'groups' | 'devices'
type Item = { name: string; kind: string }
type Overview = {
  name: string
  version: string
  realm: string
  controller: string
  mode: 'demo' | 'samba'
  controller_status: 'online' | 'degraded' | 'unknown' | 'simulated'
  counts: { users: number; groups: number; devices: number }
}
type Collection = { items: Item[]; mode: string }
type OperatorSession = { role: "viewer" | "operator" | "security"; auth_mode: "legacy" | "oidc" }
type DiagnosticCheck = {
  code: string; title: string; target: string
  status: 'pass' | 'fail' | 'unknown' | 'simulated'
  detail: string
}
type DiagnosticsReport = {
  mode: 'demo' | 'samba'; realm: string; controller: string
  checked_at: string
  summary: 'basic_checks_passed' | 'attention' | 'incomplete' | 'simulated'
  disclaimer: string
  checks: DiagnosticCheck[]
}
type AdvancedCheck = {
  code: string; title: string; status: 'pass' | 'fail' | 'unknown' | 'not_configured' | 'simulated'
  detail: string
}
type AdvancedReport = {
  mode: 'demo' | 'samba'; checked_at: string
  summary: 'simulated' | 'attention' | 'incomplete' | 'authenticated_checks_passed'
  checks: AdvancedCheck[]; disclaimer: string
}
const MENU: { id: Tab; title: string; icon: IconType; section: string }[] = [
  { id: 'overview', title: 'Command overview', icon: Activity, section: 'OPERATIONS' },
  { id: 'users', title: 'Domain identities', icon: Users, section: 'OPERATIONS' },
  { id: 'groups', title: 'Security groups', icon: Layers3, section: 'OPERATIONS' },
  { id: 'devices', title: 'Managed devices', icon: Monitor, section: 'INFRASTRUCTURE' },
  { id: 'diagnostics', title: 'Domain diagnostics', icon: Network, section: 'INFRASTRUCTURE' },
  { id: 'verification', title: 'Authenticated checks', icon: Fingerprint, section: 'INFRASTRUCTURE' },
  { id: 'about', title: 'System architecture', icon: Blocks, section: 'INFRASTRUCTURE' },
]
const SECTION_TITLES: Record<Tab, string> = {
  overview: 'Command overview', users: 'Domain identities',
  groups: 'Security groups', devices: 'Managed devices', diagnostics: 'Domain diagnostics', verification: 'Authenticated checks', about: 'System architecture',
}
const resourceIcons: Record<DataTab, IconType> = { users: Users, groups: Layers3, devices: Monitor }
const pluralLabels: Record<DataTab, string> = { users: 'user accounts', groups: 'directory groups', devices: 'computer accounts' }

function Brand({ compact = false }: { compact?: boolean }) {
  return (
    <div className="brand">
      <div className="brand-symbol"><Shield size={24} strokeWidth={1.8}/><span className="brand-bolt">ϟ</span></div>
      <div className="brand-words"><strong>DPN<span>DS</span></strong>{!compact && <small>DIRECTORY SERVICES</small>}</div>
    </div>
  )
}

function Kicker({ children }: { children: React.ReactNode }) {
  return <span className="kicker"><span className="red-dash" />{children}</span>
}

function CardHeading({ icon: Icon, eyebrow, title, right }: {
  icon: IconType; eyebrow: string; title: string; right?: React.ReactNode
}) {
  return <div className="card-heading"><div className="card-heading-title"><div className="icon-frame"><Icon size={18}/></div><div><span className="eyebrow">{eyebrow}</span><h3>{title}</h3></div></div>{right}</div>
}

function Login({ onLogin }: { onLogin: (token: string) => void }) {
  const [entry, setEntry] = useState('')
  return (
    <div className="login-root">
      <div className="login-grid"></div><div className="login-glow"></div>
      <header className="login-top"><Brand /><span className="version-tag">PLATFORM / 0.1.0</span></header>
      <main className="login-layout">
        <section className="login-hero">
          <Kicker>LINUX IDENTITY INFRASTRUCTURE</Kicker>
          <h1>CONTROL THE<br/><em>DIRECTORY.</em></h1>
          <p>Central visibility for Samba Active Directory. One secure operational surface for identities, security groups, enrolled systems, and domain health.</p>
          <div className="hero-proof">
            <div><span><Fingerprint size={19}/></span><strong>IDENTITY</strong><small>Directory intelligence</small></div>
            <div><span><ShieldCheck size={19}/></span><strong>SECURITY</strong><small>Authenticated access</small></div>
            <div><span><Server size={19}/></span><strong>INFRASTRUCTURE</strong><small>Linux-first platform</small></div>
          </div>
        </section>
        <section className="access-box">
          <div className="access-top"><div className="access-top-icon"><LockKeyhole size={26}/></div><span className="version-tag">CONTROL PLANE ACCESS</span></div>
          <Kicker>OPERATOR AUTHENTICATION</Kicker>
          <h2>Access command center</h2>
          <p>Enter a lab operator token or a short-lived, MFA-backed OIDC API access token issued by your identity provider. Browser-based OIDC login is not implemented in this release. Tokens stay only in tab memory.</p>
          <form onSubmit={e => { e.preventDefault(); if (entry.trim()) onLogin(entry.trim()) }}>
            <label htmlFor="operator-token">API OPERATOR TOKEN</label>
            <div className="token-input"><KeyRound size={18}/><input id="operator-token" type="password" autoComplete="off" spellCheck="false" placeholder="Paste your operator token" value={entry} onChange={e => setEntry(e.target.value)} /></div>
            <button className="primary-button" type="submit" disabled={!entry.trim()}>CONNECT TO DIRECTORY <ArrowRight size={18}/></button>
          </form>
          <div className="access-notice"><ShieldCheck size={17}/><span>Read-only evaluation console. No account or policy changes are permitted in v0.1.</span></div>
        </section>
      </main>
      <footer className="login-footer"><span>DPN TECHNOLOGY / DEVELOP · PIONEER · NAVIGATE</span><span>BUILT FOR CONTROL. ENGINEERED FOR TRUST.</span></footer>
    </div>
  )
}

export default function App() {
  const [token, setToken] = useState('')
  const [tab, setTab] = useState<Tab>('overview')
  const [overview, setOverview] = useState<Overview | null>(null)
  const [session, setSession] = useState<OperatorSession | null>(null)
  const [diagnostics, setDiagnostics] = useState<DiagnosticsReport | null>(null)
  const [verification, setVerification] = useState<AdvancedReport | null>(null)
  const [collections, setCollections] = useState<Partial<Record<DataTab, Item[]>>>({})
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [refresh, setRefresh] = useState(0)
  const [query, setQuery] = useState('')

  const api = useCallback(async <T,>(resource: string, abort: AbortSignal): Promise<T> => {
    const response = await fetch('/api/v1/' + resource, {
      signal: abort, headers: { Authorization: 'Bearer ' + token },
    })
    if (!response.ok) {
      if (response.status === 401) throw new Error('Authentication rejected. Verify your operator token.')
      if (response.status === 403) throw new Error('Access denied. This operation requires a higher domain monitoring role or MFA claim.')
      if (response.status === 503) throw new Error('Directory service unavailable or not configured. Check the API host, token and Samba adapter.')
      throw new Error('API request failed (' + response.status + ').')
    }
    return response.json() as Promise<T>
  }, [token])

  useEffect(() => {
    if (!token) return
    const controller = new AbortController()
    setLoading(true)
    setError('')
    const load = async () => {
      try {
        if (!session) {
          const actor = await api<OperatorSession>('session', controller.signal)
          if (!controller.signal.aborted) setSession(actor)
        }
        if (tab === 'overview' || !overview) {
          const data = await api<Overview>('overview', controller.signal)
          if (!controller.signal.aborted) setOverview(data)
        }
        if (tab === 'verification') {
          setVerification(null)
          const data = await api<AdvancedReport>('advanced-health', controller.signal)
          if (!controller.signal.aborted) setVerification(data)
        }
        if (tab === 'diagnostics') {
          setDiagnostics(null)
          const data = await api<DiagnosticsReport>('diagnostics', controller.signal)
          if (!controller.signal.aborted) setDiagnostics(data)
        }
        if (tab === 'users' || tab === 'groups' || tab === 'devices') {
          const data = await api<Collection>(tab, controller.signal)
          if (!controller.signal.aborted) setCollections(current => ({ ...current, [tab]: data.items }))
        }
      } catch (reason) {
        if (!controller.signal.aborted) setError(reason instanceof Error ? reason.message : 'Unable to contact API')
      } finally {
        if (!controller.signal.aborted) setLoading(false)
      }
    }
    void load()
    return () => controller.abort()
  }, [token, tab, refresh, api])

  const endSession = () => {
    setToken(''); setOverview(null); setSession(null); setDiagnostics(null); setVerification(null); setCollections({}); setError(''); setTab('overview'); setQuery('')
  }
  const filtered = useMemo(() => {
    if (tab !== 'users' && tab !== 'groups' && tab !== 'devices') return []
    return (collections[tab] ?? []).filter(item => item.name.toLowerCase().includes(query.toLowerCase()))
  }, [collections, query, tab])

  if (!token) return <Login onLogin={setToken}/>

  const mode = overview?.mode === 'demo' ? 'SIMULATION' : 'SAMBA DIRECTORY'
  const state = overview?.controller_status ?? 'unknown'
  const healthName = state === 'online' ? 'ONLINE' : state === 'simulated' ? 'SIMULATED' : state === 'degraded' ? 'DEGRADED' : 'UNKNOWN'
  const statusGood = state === 'online'

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="side-brand"><Brand /><div className="side-build">DPN CONTROL SYSTEMS <span>v0.1.0</span></div></div>
        <div className="tenant"><div className="tenant-icon"><Database size={19}/></div><div><span className="tenant-overline">CURRENT DIRECTORY</span><strong>{overview?.realm || 'Not connected'}</strong></div><ChevronRight size={16}/></div>
        <nav aria-label="Primary navigation">
          {MENU.map((entry, index) => {
            const Icon = entry.icon
            return <div key={entry.id}>{index === 0 || MENU[index - 1].section !== entry.section ? <p className="nav-section">{entry.section}</p> : null}
              <button className={'nav-item ' + (tab === entry.id ? 'selected' : '')} aria-current={tab === entry.id ? 'page' : undefined} onClick={() => { setTab(entry.id); setQuery('') }}>
                <Icon size={18} strokeWidth={1.8}/><span>{entry.title}</span>{tab === entry.id && <span className="active-rail"/>}
              </button>
            </div>
          })}
        </nav>
        <div className="sidebar-lower">
          <div className="sec-note"><div className="sec-note-head"><ShieldCheck size={18}/><span>SECURITY MODEL</span></div><strong>READ-ONLY ACCESS</strong><p>Mutations disabled. Authentication required on all directory endpoints.</p></div>
          <button className="disconnect" onClick={endSession}><LogOut size={17}/> Disconnect session</button>
          <div className="side-bottom">DPN TECHNOLOGY <span>© 2026</span></div>
        </div>
      </aside>
      <div className="main-container">
        <header className="topbar"><div className="crumb"><span>OPERATIONS</span><ChevronRight size={14}/><strong>{SECTION_TITLES[tab]}</strong></div><div className="top-actions"><span className="session-pill"><span className="live-dot"/>{session ? `AUTHENTICATED: ${session.role.toUpperCase()} / ${session.auth_mode.toUpperCase()}` : "TOKEN PROVIDED"}</span><button className="icon-button" onClick={() => setRefresh(v => v + 1)} title="Refresh live data" aria-label="Refresh live data"><RefreshCw size={18} className={loading ? 'spin' : ''}/></button><div className="operator-avatar"><Shield size={18}/></div></div></header>
        <main className="main-content">
          <div className="page-intro"><div><Kicker>DPN / DOMAIN OPERATIONS</Kicker><h1>{SECTION_TITLES[tab]}<span className="title-period">.</span></h1><p>Centralized identity visibility and Linux domain infrastructure intelligence.</p></div><div className="context-pill"><Wifi size={15}/>{mode}</div></div>
          {overview?.mode === 'demo' && <div className="simulation-notice"><CircleAlert size={17}/><span>SIMULATION MODE — The names, counts and system state on this screen are demonstration data, not a live domain.</span></div>}
          {error && <div className="error-notice" role="alert"><CircleAlert size={18}/><span>{error}</span><button onClick={() => setRefresh(v => v + 1)}>RETRY <ArrowRight size={14}/></button></div>}
          {tab === 'overview' && <div className="overview-page">
            <section className="hero-panel"><div className="hero-text"><Kicker>UNIFIED DIRECTORY CONTROL PLANE</Kicker><h2>Every identity.<br/>Every device.<br/><em>One command center.</em></h2><p>Samba-backed visibility into your domain. Secure by design, with no write operations exposed in this release.</p><span className="hero-readonly"><LockKeyhole size={15}/> ENFORCED READ-ONLY OPERATIONS</span></div><div className="hero-graphic" aria-hidden="true"><div className="orbit orbit-one"/><div className="orbit orbit-two"/><div className="orbit orbit-three"/><div className="orbit-center"><Shield size={64} strokeWidth={1.1}/><span>ϟ</span></div><div className="orbit-point one"/><div className="orbit-point two"/><div className="orbit-point three"/></div></section>
            <div className="stat-grid">
              {([
                {key:'users',name:'TOTAL IDENTITIES',icon:Users,caption:'Directory user accounts'},
                {key:'groups',name:'SECURITY GROUPS',icon:Layers3,caption:'Domain-managed groups'},
                {key:'devices',name:'DOMAIN DEVICES',icon:Monitor,caption:'Computer accounts'},
              ] as const).map(s => { const I=s.icon; return <div className="stat-card" key={s.key}><div className="stat-head"><span>{s.name}</span><I size={18}/></div><strong>{loading && !overview ? '—' : (overview?.counts[s.key] ?? '—')}</strong><div className="stat-foot"><span className="stat-dash"/> {s.caption}</div></div> })}
            </div>
            <div className="detail-grid">
              <section className="panel"><CardHeading icon={Server} eyebrow="INFRASTRUCTURE STATUS" title="Domain controller" right={<span className={'status-badge '+(statusGood?'good':state==='degraded'?'bad':'neutral')}><span/>{healthName}</span>}/><div className="dc-display"><div className="dc-icon"><Server size={30}/></div><div className="dc-meta"><span>DIRECTORY NODE</span><strong>{overview?.controller || 'Awaiting API data'}</strong><small>{overview?.realm || 'No domain resolved'}</small></div><span className="dc-node">DC / 01</span></div><div className="kv-list"><div><span>AUTHENTICATION ENGINE</span><strong>Samba Active Directory</strong></div><div><span>DOMAIN REALM</span><strong>{overview?.realm || '—'}</strong></div><div><span>BACKEND DATA SOURCE</span><strong>{mode}</strong></div><div><span>CONSOLE VERSION</span><strong>0.1.0 / ALPHA</strong></div></div></section>
              <section className="panel security-panel"><CardHeading icon={Eye} eyebrow="OPERATIONAL ASSURANCE" title="System capabilities"/><div className="check-list"><div><CheckCircle2 size={18}/><div><strong>Authenticated data access</strong><span>Bearer token enforced server-side</span></div></div><div><CheckCircle2 size={18}/><div><strong>Read-only command allowlist</strong><span>Directory enumeration only</span></div></div><div><CheckCircle2 size={18}/><div><strong>Explicit simulation boundary</strong><span>No fake data presented as live</span></div></div></div><div className="security-foot"><span>NOT YET AVAILABLE</span><p>OIDC / MFA, delegated RBAC, replication verification, controlled mutations and audit retention remain future milestones.</p></div></section>
            </div>
          </div>}
          {tab === 'diagnostics' && <section className="panel diagnostics-panel">
            <CardHeading icon={Network} eyebrow="READ-ONLY INFRASTRUCTURE PREFLIGHT" title="Domain connectivity diagnostics"
              right={<span className={'status-badge ' + (diagnostics?.summary === 'basic_checks_passed' ? 'good' : diagnostics?.summary === 'attention' ? 'bad' : 'neutral')}>
                <span/>{diagnostics?.summary === 'basic_checks_passed' ? 'BASIC PROBES PASSED' : diagnostics?.summary === 'attention' ? 'ATTENTION' : diagnostics?.summary === 'incomplete' ? 'INCOMPLETE' : diagnostics?.summary === 'simulated' ? 'SIMULATED' : 'NOT CHECKED'}</span>}
            />
            <div className="diagnostics-intro">
              <div><Kicker>CONFIGURED TARGET</Kicker><h2>{diagnostics?.controller ?? overview?.controller ?? 'Awaiting response'}</h2><p>{diagnostics?.realm ?? overview?.realm ?? 'No realm resolved'}</p></div>
              <div className="diagnostics-timestamp"><span>LAST SNAPSHOT</span><strong>{diagnostics ? new Date(diagnostics.checked_at).toLocaleString() : '—'}</strong><small>{diagnostics?.mode === 'demo' ? 'SIMULATED — NO PROBES' : 'ON DEMAND / NO BACKGROUND POLLING'}</small></div>
            </div>
            {diagnostics ? <div className="diagnostics-grid">
              {diagnostics.checks.map((check, index) =>
                <article className="diagnostic-card" key={check.code}>
                  <div className="diagnostic-top"><span className="diagnostic-index">{String(index + 1).padStart(2, '0')} / 05</span>
                    <span className={'diagnostic-status ' + check.status}><span className="status-indicator"/>{check.status.toUpperCase()}</span></div>
                  <h3>{check.title}</h3>
                  <span className="diagnostic-target">{check.target}</span>
                  <p>{check.detail}</p>
                </article>
              )}
            </div> : <div className="empty-state"><Network size={30}/><strong>{loading ? 'Running configured preflight' : 'No diagnostic snapshot available'}</strong><span>{loading ? 'Querying domain service records and configured controller.' : 'Refresh to obtain a new diagnostic snapshot.'}</span></div>}
            <div className="diagnostic-disclaimer"><CircleAlert size={19}/><span>{diagnostics?.disclaimer ?? 'Checks are limited to discovery, reachability and local time synchronization. They do not prove successful domain authentication.'}</span></div>
            <div className="diagnostic-footer"><div><LockKeyhole size={15}/> FIXED TARGETS · SERVER CONFIGURATION ONLY</div><button className="diagnostic-refresh" onClick={() => setRefresh(v => v + 1)} disabled={loading}><RefreshCw size={15}/> RUN CHECKS AGAIN</button></div>
          </section>}
          {tab === 'verification' && <section className="panel diagnostics-panel">
            <CardHeading icon={Fingerprint} eyebrow="OPT-IN CREDENTIAL & REPLICATION HEALTH" title="Authenticated protocol checks"
              right={<span className={'status-badge ' + (verification?.summary === 'authenticated_checks_passed' ? 'good' : verification?.summary === 'attention' ? 'bad' : 'neutral')}>
                <span/>{verification?.summary === 'authenticated_checks_passed' ? 'CHECKS PASSED' : verification?.summary === 'attention' ? 'ATTENTION' : verification?.summary === 'incomplete' ? 'INCOMPLETE' : verification?.summary === 'simulated' ? 'SIMULATED' : 'NOT CHECKED'}</span>}
            />
            <div className="diagnostics-intro">
              <div><Kicker>IDENTITY & REPLICATION VALIDATION</Kicker>
                <h2>PROVE THE CONNECTION.<br/>AUDIT THE RESULT.</h2>
                <p>Read-only checks backed by a dedicated domain identity</p></div>
              <div className="diagnostics-timestamp"><span>LAST SNAPSHOT</span><strong>{verification ? new Date(verification.checked_at).toLocaleString() : '—'}</strong><small>{verification?.mode === 'demo' ? 'SIMULATION ONLY' : 'OPT-IN / ON DEMAND'}</small></div>
            </div>
            {verification ? <div className="diagnostics-grid">
              {verification.checks.map((check, index) => <article className="diagnostic-card" key={check.code}>
                <div className="diagnostic-top"><span className="diagnostic-index">{String(index + 1).padStart(2, '0')} / 03</span>
                  <span className={'diagnostic-status ' + check.status}><span className="status-indicator"/>{check.status.replace('_',' ').toUpperCase()}</span></div>
                <h3>{check.title}</h3><span className="diagnostic-target">{check.code.toUpperCase()}</span>
                <p>{check.detail}</p>
              </article>)}
            </div> : <div className="empty-state"><Fingerprint size={30}/><strong>{loading ? 'Evaluating configured probes' : 'No authenticated snapshot'}</strong><span>Checks run only when configured by the administrator.</span></div>}
            <div className="diagnostic-disclaimer"><CircleAlert size={19}/><span>{verification?.disclaimer ?? 'No production-grade domain health guarantees are provided by these checks.'}</span></div>
            <div className="diagnostic-footer"><div><LockKeyhole size={15}/> NO LDAP WRITES · NO BROWSER CREDENTIALS</div><button className="diagnostic-refresh" onClick={() => setRefresh(v => v + 1)} disabled={loading}><RefreshCw size={15}/> RUN CHECKS AGAIN</button></div>
          </section>}
          {(tab === 'users' || tab === 'groups' || tab === 'devices') && <section className="panel collection-panel"><CardHeading icon={resourceIcons[tab]} eyebrow="DIRECTORY INVENTORY / READ ONLY" title={pluralLabels[tab]} right={<span className="count-pill">{filtered.length} SHOWN</span>}/><div className="collection-tools"><div className="search-control"><Search size={17}/><input placeholder={'Search ' + pluralLabels[tab] + '...'} aria-label={'Search ' + pluralLabels[tab]} value={query} onChange={e => setQuery(e.target.value)} /></div><span className="inventory-message"><Eye size={15}/> OBSERVATION ONLY</span></div><div className="record-header"><span>DIRECTORY OBJECT</span><span>OBJECT TYPE</span></div>{filtered.length ? filtered.map((item, i) => { const I=resourceIcons[tab]; return <div className="record-row" key={item.name+i}><div className="record-identity"><div className="record-icon"><I size={18}/></div><div><strong>{item.name}</strong><small>{overview?.realm}</small></div></div><div className="record-kind">{item.kind.toUpperCase()}</div></div> }) : <div className="empty-state"><Database size={30}/><strong>{loading ? 'Loading directory records' : 'No records to display'}</strong><span>{loading ? 'Reading the directory adapter…' : 'Search or refresh to check for directory objects.'}</span></div>}<div className="table-footer"><span>{filtered.length} matching records</span><span>NO EDIT ACTIONS IN THIS RELEASE</span></div></section>}
          {tab === 'about' && <section className="panel about-panel"><CardHeading icon={Blocks} eyebrow="ENGINEERING REFERENCE" title="Directory services architecture"/><div className="architecture-flow"><div><div className="flow-icon"><Monitor size={24}/></div><strong>DPN CONSOLE</strong><span>React / TypeScript</span></div><ArrowRight/><div><div className="flow-icon"><ShieldCheck size={24}/></div><strong>CONTROL API</strong><span>FastAPI / Token gate</span></div><ArrowRight/><div><div className="flow-icon"><Terminal size={24}/></div><strong>SAMBA AD DC</strong><span>Read-only CLI adapter</span></div></div><div className="about-grid"><div><Kicker>AVAILABLE NOW</Kicker><h3>Initial foundation</h3><p>Domain overview, user inventory, group inventory, computer accounts and controller service status through a constrained API.</p></div><div><Kicker>PLANNED MILESTONES</Kicker><h3>Enterprise control plane</h3><p>Audited user changes, RBAC/MFA, Linux host policy orchestration, replication checks, authenticated Kerberos/LDAP checks and secure remote agents.</p></div></div><div className="architecture-footer"><HardDrive size={18}/> DPN DS relies on Samba for directory protocols and data. It does not replace AD DC, LDAP or Kerberos engines. <ArrowUpRight size={16}/></div></section>}
          <footer className="main-footer"><span>© 2026 DPN TECHNOLOGY · DEVELOP PIONEER NAVIGATE</span><span><span className="footer-dot"/> DPN DS / ALPHA 0.1.0</span></footer>
        </main>
      </div>
    </div>
  )
}
