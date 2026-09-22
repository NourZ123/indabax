import { ArrowRight, ArrowUpRight, Clock3, ShieldCheck, ShieldX } from 'lucide-react';
import { Link } from 'react-router-dom';
import { countByDecision, DomainLabel, EmptyState, MetricCard, Outcome, Panel, SectionHeading, StatusDot, formatTimestamp } from '../components/Common';
import type { Decision, Run } from '../types/sentinel';

const WEEKDAYS = 7;
function lastSevenDays(runs: Run[]): { label: string; allow: number; block: number; escalate: number; rewrite: number }[] {
  const end = new Date(); end.setHours(0, 0, 0, 0);
  return Array.from({ length: WEEKDAYS }, (_, idx) => {
    const day = new Date(end); day.setDate(end.getDate() - (WEEKDAYS - idx - 1));
    const next = new Date(day); next.setDate(next.getDate() + 1);
    const events = runs.flatMap((run) => run.events.filter((event) => {
      const value = new Date(run.createdAt).getTime(); return value >= day.getTime() && value < next.getTime();
    }));
    return { label: day.toLocaleDateString(undefined, { weekday: 'short' }), ...countByDecision(events) };
  });
}

export function OverviewPage({ runs }: { runs: Run[] }) {
  const events = runs.flatMap((run) => run.events);
  const counts = countByDecision(events);
  const activity = lastSevenDays(runs);
  const maxDay = Math.max(1, ...activity.map((day) => day.allow + day.block + day.escalate + day.rewrite));
  const findings = runs.flatMap((run) => run.events.filter((event) => event.decision !== 'allow').map((event) => ({ run, event }))).slice(0, 5);
  const attackRuns = runs.filter((run) => run.attackSuccess !== null);
  const stopped = attackRuns.filter((run) => run.attackSuccess === false).length;
  return <div className="page-stack">
    <SectionHeading title="Overview" description="A summary of recorded agent activity and defense interventions." action={<Link className="button button--light" to="/runs">Explore runs <ArrowUpRight size={16} /></Link>} />
    <div className="metrics-grid metrics-grid--four">
      <MetricCard label="Recorded runs" value={runs.length} icon={Clock3} description="Within selected time range" />
      <MetricCard label="Allowed actions" value={counts.allow} icon={ShieldCheck} color="var(--allowed)" description="Actions permitted unchanged" />
      <MetricCard label="Blocked actions" value={counts.block} icon={ShieldX} color="var(--blocked)" description="Actions prevented" />
      <MetricCard label="Attacks failed" value={attackRuns.length > 0 ? `${stopped} / ${attackRuns.length}` : '—'} color="var(--text-primary)" description="Only runs with recorded outcomes" />
    </div>
    <div className="overview-main-grid">
      <Panel title="Decision activity" action={<span className="panel-meta">Last seven save dates</span>}>
        <p className="panel-subtitle">Decisions grouped by when their run artifact was saved (simulator event timestamps use a logical clock).</p>
        <div className="activity-chart" role="img" aria-label="Stacked bars showing action decisions over the last seven days">
          {activity.map((day, idx) => <div className="activity-column" key={idx}>
            <div className="activity-bar" title={`${day.label}: ${day.allow} allowed, ${day.block} blocked, ${day.escalate} escalated, ${day.rewrite} rewritten`}>
              {(['rewrite', 'escalate', 'block', 'allow'] as Decision[]).map((kind) => <span key={kind} className={`activity-segment activity-segment--${kind}`} style={{ height: `${day[kind] / maxDay * 100}%` }} />)}
            </div><span>{day.label}</span>
          </div>)}
        </div>
        <div className="activity-legend"><StatusDot status="allow" /><StatusDot status="block" /><StatusDot status="escalate" /><StatusDot status="rewrite" /></div>
      </Panel>
      <Panel title="Domain coverage"><p className="panel-subtitle">Runs grouped by simulated organization domain.</p>
        <div className="coverage-list">{(['enterprise', 'finance', 'soc'] as const).map((domain) => {
          const count = runs.filter((run) => run.domain === domain).length;
          return <div key={domain} className="coverage-row"><DomainLabel domain={domain} /><div className="coverage-track"><span style={{ width: `${runs.length ? count / runs.length * 100 : 0}%` }} /></div><strong>{count}</strong></div>;
        })}</div>
        <div className="mini-breakdown"><div><strong>{counts.escalate}</strong><span>Escalated</span></div><div><strong>{counts.rewrite}</strong><span>Rewritten</span></div><div><strong>{runs.reduce((sum, run) => sum + run.events.length, 0)}</strong><span>All actions</span></div></div>
      </Panel>
    </div>
    <div className="overview-main-grid overview-main-grid--equal">
      <Panel title="Recent runs" action={<Link className="quiet-link" to="/runs">View all <ArrowRight size={15} /></Link>}>
        {runs.length === 0 ? <EmptyState title="No recorded runs" description="Try a wider time range or connect a simulator artifact." /> : <div className="compact-list">{runs.slice(0, 5).map((run) => <Link className="compact-list__item" key={run.id} to={`/runs/${run.id}`}>
          <div><strong>{run.id}</strong><span>{run.title}</span></div><Outcome outcome={run.outcome} /><ArrowRight size={15} className="compact-list__arrow" />
        </Link>)}</div>}
      </Panel>
      <Panel title="Recent security findings" action={<Link className="quiet-link" to="/incidents">Investigate <ArrowRight size={15} /></Link>}>
        {findings.length === 0 ? <EmptyState title="No interventions" description="No blocked, escalated or rewritten actions appear in this time range." /> : <div className="compact-list">{findings.map(({ run, event }) => <Link className="compact-list__item" to={`/runs/${run.id}`} key={event.id}>
          <div><strong>{event.tool}</strong><span>{run.id} · {formatTimestamp(event.occurredAt)}</span></div><StatusDot status={event.decision} /><ArrowRight size={15} className="compact-list__arrow" />
        </Link>)}</div>}
      </Panel>
    </div>
  </div>;
}
