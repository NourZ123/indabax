import type { ReactNode } from 'react';
import type { LucideIcon } from 'lucide-react';
import { Download, Inbox } from 'lucide-react';
import type { Decision, DisplayStatus, Domain } from '../types/sentinel';

const LABELS: Record<DisplayStatus, string> = {
  allow: 'Allowed', block: 'Blocked', escalate: 'Escalated', rewrite: 'Rewritten',
  completed: 'Completed', online: 'Online', offline: 'Offline',
};

export function StatusDot({ status, label, className = '' }: { status: DisplayStatus; label?: string; className?: string }) {
  return <span className={`status status--${status} ${className}`}><span className="status__dot" aria-hidden="true" />{label ?? LABELS[status]}</span>;
}

export function Outcome({ outcome }: { outcome: 'attack_blocked' | 'attack_succeeded' | 'task_completed' | 'task_incomplete' | 'attack_failed' | 'not_evaluated' }) {
  const map = {
    attack_blocked: ['block', 'Attack blocked'], attack_succeeded: ['block', 'Attack succeeded'],
    task_completed: ['completed', 'Task completed'], task_incomplete: ['escalate', 'Task incomplete'],
    attack_failed: ['completed', 'Attack failed'], not_evaluated: ['offline', 'Not evaluated'],
  } as const;
  const [status, label] = map[outcome];
  return <StatusDot status={status} label={label} />;
}

export function DomainLabel({ domain }: { domain: Domain }) {
  return <span className="domain-label">{domain === 'soc' ? 'SOC' : domain[0].toUpperCase() + domain.slice(1)}</span>;
}

export function Panel({ children, className = '', title, action }: { children: ReactNode; className?: string; title?: string; action?: ReactNode }) {
  return <section className={`panel ${className}`}>
    {(title || action) && <div className="panel__head">{title && <h2>{title}</h2>}{action}</div>}
    {children}
  </section>;
}

export function MetricCard({ icon: Icon, label, value, description, color, trend }: { icon?: LucideIcon; label: string; value: string | number; description?: string; color?: string; trend?: string }) {
  return <div className="metric-card">
    <div className="metric-card__top"><span>{label}</span>{Icon && <Icon size={17} strokeWidth={1.8} aria-hidden="true" />}</div>
    <div className="metric-card__bottom"><strong style={color ? { color } : undefined}>{value}</strong>{trend && <span className="metric-card__trend">{trend}</span>}</div>
    {description && <p>{description}</p>}
  </div>;
}

export function SectionHeading({ title, description, action }: { title: string; description?: string; action?: ReactNode }) {
  return <div className="section-heading"><div><h1>{title}</h1>{description && <p>{description}</p>}</div>{action}</div>;
}

export function EmptyState({ title, description, action }: { title: string; description: string; action?: ReactNode }) {
  return <div className="empty-state"><Inbox size={26} strokeWidth={1.4} aria-hidden="true" /><h3>{title}</h3><p>{description}</p>{action}</div>;
}

export function Field({ label, value }: { label: string; value: ReactNode }) {
  return <div className="field"><span>{label}</span><strong>{value}</strong></div>;
}

export function TabBar<T extends string>({ tabs, value, onChange, ariaLabel = 'View' }: { tabs: { key: T; label: string }[]; value: T; onChange: (value: T) => void; ariaLabel?: string }) {
  return <div className="tabs" role="tablist" aria-label={ariaLabel}>
    {tabs.map((tab) => <button key={tab.key} type="button" role="tab" aria-selected={value === tab.key} className={`tab ${value === tab.key ? 'tab--active' : ''}`} onClick={() => onChange(tab.key)}>{tab.label}</button>)}
  </div>;
}

export function RiskBar({ value, color, label }: { value: number | null | undefined; color?: string; label?: string }) {
  const amount = value === null || value === undefined ? null : Math.max(0, Math.min(1, value));
  return <div className="risk-row">{label && <span className="risk-row__label">{label}</span>}<div className="risk-track"><span style={{ width: amount === null ? '0%' : `${amount * 100}%`, background: color || (amount !== null && amount >= 0.7 ? 'var(--blocked)' : amount !== null && amount >= 0.4 ? 'var(--escalated)' : 'var(--allowed)') }} /></div><span className="risk-row__value">{amount === null ? '—' : amount.toFixed(2)}</span></div>;
}

export function DownloadButton({ onClick, label = 'Export' }: { onClick: () => void; label?: string }) {
  return <button className="button button--light" type="button" onClick={onClick}><Download size={15} aria-hidden="true" />{label}</button>;
}

export function asPercent(value: number | null | undefined): string {
  return value === null || value === undefined ? '—' : `${Math.round(value * 100)}%`;
}
export function formatDuration(ms: number | null | undefined): string {
  return ms === null || ms === undefined ? '—' : ms < 1_000 ? `${ms} ms` : `${(ms / 1_000).toFixed(2)} s`;
}
export function formatTimestamp(iso: string): string {
  return new Date(iso).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}
export function formatClock(iso: string): string {
  return new Date(iso).toLocaleTimeString(undefined, { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit', fractionalSecondDigits: 3 });
}
export function countByDecision(events: { decision: Decision }[]): Record<Decision, number> {
  return events.reduce<Record<Decision, number>>((counts, event) => ({ ...counts, [event.decision]: counts[event.decision] + 1 }), { allow: 0, block: 0, escalate: 0, rewrite: 0 });
}
