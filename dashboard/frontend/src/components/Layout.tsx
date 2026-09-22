import { useEffect, useMemo, useRef, useState } from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import {
  Activity, AlertTriangle, CalendarDays, ChevronDown, CircleHelp, Database, FlaskConical,
  LayoutDashboard, ListTree, Menu, Search, Settings, Shield, ShieldCheck, X,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import type { ReactNode } from 'react';
import { IS_DEMO } from '../services/api';
import type { Run, TimeRange } from '../types/sentinel';
import { StatusDot } from './Common';

type NavItem = { name: string; to: string; icon: LucideIcon; end?: boolean };
const primary: NavItem[] = [
  { name: 'Overview', to: '/overview', icon: LayoutDashboard },
  { name: 'Runs', to: '/runs', icon: ListTree },
  { name: 'Evaluations', to: '/evaluations', icon: Activity },
  { name: 'Policies', to: '/policies', icon: ShieldCheck },
];
const secondary: NavItem[] = [
  { name: 'Incidents', to: '/incidents', icon: AlertTriangle },
  { name: 'Playground', to: '/playground', icon: FlaskConical },
  { name: 'Data & Artifacts', to: '/artifacts', icon: Database },
  { name: 'Settings', to: '/settings', icon: Settings },
];

function Navigation({ onNavigate }: { onNavigate: () => void }) {
  const renderItem = (item: NavItem) => <NavLink
    key={item.to} to={item.to} onClick={onNavigate} end={item.end} className={({ isActive }) => `nav-item ${isActive ? 'nav-item--active' : ''}`}>
    <item.icon size={17} strokeWidth={1.8} aria-hidden="true" /><span>{item.name}</span>
  </NavLink>;
  return <nav aria-label="Main navigation" className="sidebar__nav">
    <div className="nav-group">{primary.map(renderItem)}</div>
    <div className="nav-separator" />
    <div className="nav-group">{secondary.map(renderItem)}</div>
  </nav>;
}

function GlobalSearch({ runs }: { runs: Run[] }) {
  const [query, setQuery] = useState('');
  const [focused, setFocused] = useState(false);
  const navigate = useNavigate();
  const inputRef = useRef<HTMLInputElement>(null);
  useEffect(() => {
    const focusShortcut = (event: KeyboardEvent) => {
      const element = event.target as HTMLElement | null;
      const typing = element?.matches('input, textarea, select, [contenteditable=\"true\"]');
      if (event.key === '/' && !typing && !event.ctrlKey && !event.metaKey && !event.altKey) {
        event.preventDefault(); inputRef.current?.focus();
      }
    };
    window.addEventListener('keydown', focusShortcut);
    return () => window.removeEventListener('keydown', focusShortcut);
  }, []);
  const results = useMemo(() => query.trim().length === 0 ? [] : runs.filter((run) =>
    [run.id, run.scenario, run.title, run.domain, ...run.events.map((event) => event.tool)]
      .some((value) => value.toLowerCase().includes(query.trim().toLowerCase()))).slice(0, 6), [runs, query]);
  const open = focused && query.trim().length > 0;
  const select = (runId: string) => { navigate(`/runs/${runId}`); setQuery(''); setFocused(false); };
  return <div className="global-search">
    <Search size={17} strokeWidth={1.9} aria-hidden="true" />
    <input ref={inputRef}
      value={query} onChange={(event) => setQuery(event.target.value)} onFocus={() => setFocused(true)}
      onKeyDown={(event) => {
        if (event.key === 'Escape') { setQuery(''); setFocused(false); }
        if (event.key === 'Enter' && results.length > 0) select(results[0].id);
      }}
      onBlur={() => window.setTimeout(() => setFocused(false), 120)}
      aria-label="Search runs, tools or scenarios" placeholder="Search runs, tools, or scenarios..."
      autoComplete="off"
    />
    <span className="key-hint">/</span>
    {open && <div className="search-results" role="region" aria-label="Search results">
      <div className="search-results__label">Matching runs</div>
      {results.length === 0 ? <div className="search-results__empty">No matching runs</div> : results.map((run) =>
        <button key={run.id} type="button" onMouseDown={(event) => event.preventDefault()} onClick={() => select(run.id)}>
          <strong>{run.id}</strong><span>{run.scenario}</span><small>{run.domain}</small>
        </button>)}
    </div>}
  </div>;
}

export function AppShell({ children, runs, timeRange, setTimeRange }: {
  children: ReactNode; runs: Run[]; timeRange: TimeRange; setTimeRange: (value: TimeRange) => void;
}) {
  const [mobileOpen, setMobileOpen] = useState(false);
  const navigate = useNavigate();
  return <div className="app-shell">
    {mobileOpen && <button className="mobile-overlay" aria-label="Close navigation" onClick={() => setMobileOpen(false)} />}
    <aside className={`sidebar ${mobileOpen ? 'sidebar--open' : ''}`}>
      <div className="brand"><div className="brand__mark"><Shield size={25} strokeWidth={2.25} /></div><div><strong>SENTINEL</strong><span>Agent Defense Console</span></div></div>
      <Navigation onNavigate={() => setMobileOpen(false)} />
      <div className="sidebar__bottom">
        {IS_DEMO ? <span className="side-status"><span className="side-status__dot side-status__dot--demo" />Demo workspace</span>
          : <span className="side-status"><StatusDot status="online" label="Dashboard connected" /></span>}
        <small>Frontend v0.1.0</small>
      </div>
    </aside>
    <div className="app-main">
      <header className="topbar">
        <button type="button" className="icon-button mobile-menu" aria-label="Open navigation" onClick={() => setMobileOpen(true)}><Menu size={20} /></button>
        <GlobalSearch runs={runs} />
        <div className="topbar__right">
          <div className="time-select"><CalendarDays size={17} aria-hidden="true" />
            <select value={timeRange} aria-label="Time range" onChange={(event) => setTimeRange(event.target.value as TimeRange)}>
              <option value="24h">Last 24 hours</option><option value="7d">Last 7 days</option><option value="30d">Last 30 days</option><option value="all">All time</option>
            </select><ChevronDown size={15} aria-hidden="true" />
          </div>
          <button type="button" className="icon-button topbar__help" aria-label="About this dashboard" title="About this dashboard" onClick={() => navigate('/settings')}><CircleHelp size={19} strokeWidth={1.8} /></button>
          <div className="account"><span className="account__avatar">ST</span><span className="account__label">SENTINEL</span></div>
        </div>
      </header>
      {IS_DEMO ? <div className="demo-banner"><span className="demo-banner__dot" /> <strong>Demo data</strong> — illustrative traces and evaluation figures. No simulator or defense is connected yet.</div> : <div className="demo-banner"><span className="demo-banner__dot" /> <strong>Recorded artifacts</strong> — real simulator decisions and evaluations; sensitive text is redacted server-side. Module scores and model identity are shown only if recorded.</div>}
      <main id="main-content" className="page-content">{children}</main>
    </div>
  </div>;
}

export function MobileCloseButton({ close }: { close: () => void }) {
  return <button type="button" className="icon-button" aria-label="Close" onClick={close}><X size={18} /></button>;
}
