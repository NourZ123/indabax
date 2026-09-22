import { useMemo, useState } from 'react';
import { ArrowLeft, ArrowRight, ChevronLeft, ChevronRight, ClipboardCopy, Download, FileJson, Filter, Search, ShieldAlert } from 'lucide-react';
import { Link, useParams } from 'react-router-dom';
import {
  asPercent, countByDecision, DomainLabel, DownloadButton, EmptyState, Field, formatClock, formatDuration,
  formatTimestamp, MetricCard, Outcome, Panel, RiskBar, SectionHeading, StatusDot, TabBar,
} from '../components/Common';
import { downloadCSV, downloadJSON } from '../services/api';
import type { Decision, Run, SignalName, TraceEvent } from '../types/sentinel';

type DetailTab = 'trace' | 'summary' | 'artifacts' | 'evaluator';
type InspectorTab = 'details' | 'analysis' | 'provenance' | 'raw';

const ALL_DECISIONS: Decision[] = ['allow', 'block', 'escalate', 'rewrite'];
const SIGNAL_ORDER: SignalName[] = ['Information flow', 'Injection', 'Goal alignment', 'Policy', 'History'];

function displayBool(value: boolean | null): string { return value === null ? 'Not evaluated' : value ? 'Yes' : 'No'; }

export function RunListPage({ runs }: { runs: Run[] }) {
  const [query, setQuery] = useState('');
  const [domain, setDomain] = useState('all');
  const [outcome, setOutcome] = useState('all');
  const matches = useMemo(() => runs.filter((run) => {
    if (domain !== 'all' && run.domain !== domain) return false;
    if (outcome !== 'all' && run.outcome !== outcome) return false;
    return `${run.id} ${run.title} ${run.scenario} ${run.domain}`.toLowerCase().includes(query.toLowerCase());
  }).sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()), [runs, query, domain, outcome]);
  const counts = runs.flatMap((run) => run.events);
  const aggregate = countByDecision(counts);
  return <div className="page-stack">
    <SectionHeading title="Runs" description="Browse recorded agent executions and investigate defense decisions."
      action={<DownloadButton label="Export runs" onClick={() => downloadCSV('sentinel-runs.csv', ['Run','Scenario','Domain','Started','Outcome','Task success','Attack success'],
        matches.map((run) => [run.id, run.scenario, run.domain, run.createdAt, run.outcome, run.taskSuccess, run.attackSuccess]))} />} />
    <div className="metrics-grid metrics-grid--four">
      <MetricCard label="Recorded runs" value={runs.length} description="Within selected time range" />
      <MetricCard label="Allowed actions" value={aggregate.allow} color="var(--allowed)" />
      <MetricCard label="Blocked actions" value={aggregate.block} color="var(--blocked)" />
      <MetricCard label="Escalated / rewritten" value={aggregate.escalate + aggregate.rewrite} color="var(--escalated)" />
    </div>
    <Panel className="run-list-panel">
      <div className="table-toolbar">
        <div className="inline-search"><Search size={16} aria-hidden="true" /><input placeholder="Search run ID or scenario" aria-label="Search runs" value={query} onChange={(e) => setQuery(e.target.value)} /></div>
        <div className="table-toolbar__controls"><Filter size={16} className="toolbar-filter-icon" aria-hidden="true" />
          <select className="select-control" aria-label="Filter domain" value={domain} onChange={(e) => setDomain(e.target.value)}><option value="all">All domains</option><option value="enterprise">Enterprise</option><option value="finance">Finance</option><option value="soc">SOC</option><option value="unknown">Unknown</option></select>
          <select className="select-control" aria-label="Filter outcome" value={outcome} onChange={(e) => setOutcome(e.target.value)}><option value="all">All outcomes</option><option value="attack_blocked">Attack blocked (demo)</option><option value="attack_failed">Attack failed</option><option value="not_evaluated">Not evaluated</option><option value="attack_succeeded">Attack succeeded</option><option value="task_completed">Task completed</option><option value="task_incomplete">Task incomplete</option></select>
        </div>
      </div>
      {matches.length === 0 ? <EmptyState title="No matching runs" description="Try a different search, domain or time range." /> : <div className="table-scroll">
        <table className="data-table">
          <thead><tr><th>Run</th><th>Scenario</th><th>Domain</th><th>Started</th><th>Actions</th><th>Outcome</th><th aria-label="Open run" /></tr></thead>
          <tbody>{matches.map((run) => <tr key={run.id}>
            <td><Link className="table-link table-link--strong" to={`/runs/${run.id}`}>{run.id}</Link></td>
            <td><div className="table-primary">{run.title}</div><div className="table-secondary mono">{run.scenario}</div></td>
            <td><DomainLabel domain={run.domain} /></td><td className="nowrap">{formatTimestamp(run.createdAt)}</td>
            <td>{run.events.length}</td><td><Outcome outcome={run.outcome} /></td>
            <td><Link className="table-open" aria-label={`Open ${run.id}`} to={`/runs/${run.id}`}><ArrowRight size={16} /></Link></td>
          </tr>)}</tbody>
        </table>
      </div>}
      <div className="table-footer">Showing {matches.length} of {runs.length} runs</div>
    </Panel>
  </div>;
}

export function RunDetailsPage({ runs }: { runs: Run[] }) {
  const { runId } = useParams();
  const run = runs.find((item) => item.id === runId);
  if (!run) return <div className="page-stack"><Link className="back-link" to="/runs"><ArrowLeft size={16} /> Back to runs</Link><EmptyState title="Run not found" description={`No saved run has ID ${runId || 'unknown'}.`} /></div>;
  return <RunDetailsView key={run.id} run={run} />;
}

function RunDetailsView({ run }: { run: Run }) {
  const [tab, setTab] = useState<DetailTab>('trace');
  const [selectedId, setSelectedId] = useState(run.events.find((step) => step.decision === 'block')?.id ?? run.events[0]?.id ?? '');
  const [decisionFilter, setDecisionFilter] = useState<Decision | 'all'>('all');
  const selected = run.events.find((event) => event.id === selectedId) ?? run.events[0];
  const visibleSteps = decisionFilter === 'all' ? run.events : run.events.filter((event) => event.decision === decisionFilter);
  const counts = countByDecision(run.events);
  return <div className="page-stack page-stack--run">
    <div className="run-heading">
      <div className="run-heading__left">
        <Link className="back-icon" to="/runs" aria-label="Back to runs"><ArrowLeft size={21} strokeWidth={1.8} /></Link>
        <div><div className="run-heading__title"><h1>{run.id}</h1><Outcome outcome={run.outcome} /></div>
          <p>Scenario: <span className="mono">{run.scenario}</span></p><p>{run.title}</p></div>
      </div>
      <div className="run-meta"><Field label="Started" value={formatTimestamp(run.createdAt)} /><Field label="Duration" value={formatDuration(run.durationMs)} /><Field label="Model" value={run.model} /><Field label="Status" value={<Outcome outcome={run.outcome} />} /></div>
    </div>
    <TabBar value={tab} onChange={setTab} ariaLabel="Run views" tabs={[{ key: 'trace', label: 'Trace' }, { key: 'summary', label: 'Summary' }, { key: 'artifacts', label: 'Artifacts' }, { key: 'evaluator', label: 'Evaluator' }]} />
    {tab === 'trace' && <>
      <div className="metrics-grid metrics-grid--run">
        <MetricCard label="Total steps" value={run.events.length} />
        <MetricCard label="Allowed" value={counts.allow} color="var(--allowed)" trend={asPercent(counts.allow / (run.events.length || 1))} />
        <MetricCard label="Escalated" value={counts.escalate} color="var(--escalated)" trend={asPercent(counts.escalate / (run.events.length || 1))} />
        <MetricCard label="Blocked" value={counts.block} color="var(--blocked)" trend={asPercent(counts.block / (run.events.length || 1))} />
        <MetricCard label="Wall-clock duration" value={formatDuration(run.durationMs)} />
      </div>
      <div className="run-workspace">
        <Panel className="trace-panel" title="Execution trace" action={<select value={decisionFilter} className="select-control" aria-label="Filter trace decisions" onChange={(e) => setDecisionFilter(e.target.value as Decision | 'all')}>
          <option value="all">All steps</option>{ALL_DECISIONS.map((item) => <option key={item} value={item}>{item === 'allow' ? 'Allowed' : item === 'block' ? 'Blocked' : item === 'escalate' ? 'Escalated' : 'Rewritten'}</option>)}
        </select>}>
          <p className="panel-subtitle">Chronological list of agent actions and defense decisions.</p>
          {visibleSteps.length === 0 ? <EmptyState title="No steps in this category" description="Change the decision filter to inspect other actions." /> : <div className="table-scroll trace-table-scroll">
            <table className="data-table trace-table"><thead><tr><th>#</th><th>Time</th><th>Action</th><th>Tool / Type</th><th>Decision</th><th>Defense latency</th></tr></thead>
              <tbody>{visibleSteps.map((step) => <tr key={step.id} className={`trace-row ${selectedId === step.id ? 'trace-row--selected' : ''}`} onClick={() => setSelectedId(step.id)} onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setSelectedId(step.id); } }} tabIndex={0} aria-selected={selectedId === step.id}>
                <td className="step-number"><span className={`step-indicator step-indicator--${step.decision}`} />{String(step.stepId ?? step.index).padStart(2, '0')}</td>
                <td className="nowrap time-cell">{formatClock(step.occurredAt)}</td>
                <td className="trace-description">{step.description}</td><td className="mono tool-cell">{step.tool}</td>
                <td><StatusDot status={step.decision} /></td><td className="nowrap">{formatDuration(step.durationMs)}</td>
              </tr>)}</tbody>
            </table>
          </div>}
        </Panel>
        {selected ? <DecisionInspector event={selected} run={run} onPrevious={() => setSelectedId(run.events[Math.max(0, run.events.findIndex((item) => item.id === selectedId) - 1)].id)}
          onNext={() => setSelectedId(run.events[Math.min(run.events.length - 1, run.events.findIndex((item) => item.id === selectedId) + 1)].id)} /> : <Panel><EmptyState title="No events recorded" description="No execution trace was returned for this run." /></Panel>}
      </div>
      <div className="run-bottom-grid">
        <Panel title={`Risk signals · step ${selected?.index ?? '—'}`}><p className="panel-subtitle">Defense-reported scores for the selected action; not calibrated probabilities.</p>
          {selected ? <div className="risk-list">{SIGNAL_ORDER.map((signal) => <RiskBar key={signal} label={signal} value={selected.signals[signal]} />)}</div> : <EmptyState title="No scores" description="Select an action to see its scores." />}
        </Panel>
        <Panel title="Decision distribution"><DecisionDistribution counts={counts} total={run.events.length} /></Panel>
      </div>
    </>}
    {tab === 'summary' && <RunSummary run={run} />}
    {tab === 'artifacts' && <RunArtifacts run={run} />}
    {tab === 'evaluator' && <RunEvaluator run={run} />}
  </div>;
}

function DecisionInspector({ event, run, onPrevious, onNext }: { event: TraceEvent; run: Run; onPrevious: () => void; onNext: () => void }) {
  const [tab, setTab] = useState<InspectorTab>('details');
  const [copied, setCopied] = useState(false);
  const copy = async () => { try { await navigator.clipboard.writeText(JSON.stringify(event.arguments, null, 2)); setCopied(true); window.setTimeout(() => setCopied(false), 1800); } catch { setCopied(false); } };
  return <Panel className="inspector-panel">
    <div className="inspector__heading"><h2>Step {String(event.stepId ?? event.index).padStart(2, '0')} — <span className={`text--${event.decision}`}>{event.decision === 'allow' ? 'Allowed' : event.decision === 'block' ? 'Blocked' : event.decision === 'escalate' ? 'Escalated' : 'Rewritten'}</span></h2>
      <div className="inspector__arrows"><button type="button" className="icon-button icon-button--border" aria-label="Previous action" disabled={event.index <= 1} onClick={onPrevious}><ChevronLeft size={18} /></button><button type="button" className="icon-button icon-button--border" aria-label="Next action" disabled={event.index >= run.events.length} onClick={onNext}><ChevronRight size={18} /></button></div>
    </div>
    <div className="inspector__subject"><div className="inspector__tool-icon"><ShieldAlert size={23} strokeWidth={1.7} /></div><div><h3 className="mono">{event.tool}</h3><p>{event.description}</p></div></div>
    <TabBar value={tab} onChange={setTab} ariaLabel="Selected action detail" tabs={[{ key: 'details', label: 'Details' }, { key: 'analysis', label: 'Defense analysis' }, { key: 'provenance', label: 'Provenance' }, { key: 'raw', label: 'Raw data' }]} />
    <div className="inspector__content">
      {tab === 'details' && <>
        <div className="inspect-section"><div className="inspect-section__title"><h4>Tool arguments</h4><button type="button" className="icon-button" onClick={copy} aria-label="Copy tool arguments" title="Copy tool arguments"><ClipboardCopy size={15} /></button>{copied && <span className="copy-note">Copied</span>}</div>
          <pre className="json-box">{JSON.stringify(event.arguments, null, 2)}</pre></div>
        <div className="inspect-section"><h4>Decision</h4><div className="decision-callout"><StatusDot status={event.decision} /><p>{event.explanation}</p></div></div>
        <div className="inspect-section"><h4>Reason codes</h4>{event.reasonCodes.length > 0 ? <div className="reason-list">{event.reasonCodes.map((code) => <div key={code} className="reason-item"><code>{code}</code></div>)}</div> : <p className="muted">No reason codes recorded.</p>}</div>
        {event.rewrittenAction && <div className="inspect-section"><h4>Rewritten action</h4><pre className="json-box">{JSON.stringify(event.rewrittenAction, null, 2)}</pre></div>}
        <div className="inspect-section"><h4>Data flow</h4><DataFlow event={event} /></div>
        {event.result && <div className="inspect-section"><h4>Observed result</h4><p className="small-text">{event.result}</p></div>}
      </>}
      {tab === 'analysis' && <>
        <div className="analysis-feature"><div><span className="eyebrow">Aggregate risk</span><strong>{event.riskScore === null ? 'Not reported' : event.riskScore.toFixed(2)}</strong></div><div><span className="eyebrow">Confidence</span><strong>{event.confidence === null ? 'Not reported' : asPercent(event.confidence)}</strong></div></div>
        <div className="inspect-section"><h4>Module-level risk signals</h4><div className="risk-list">{SIGNAL_ORDER.map((signal) => <RiskBar key={signal} label={signal} value={event.signals[signal]} />)}</div><p className="help-copy">Heuristic scores represent defense signals, not observed attack probabilities.</p></div>
        <div className="inspect-section"><h4>Decision rationale</h4><p className="small-text">{event.explanation}</p></div>
        <div className="inspect-section"><h4>Recorded reason codes</h4><div className="reason-list">{event.reasonCodes.map((code) => <div className="reason-item" key={code}><code>{code}</code></div>)}</div></div>
      </>}
      {tab === 'provenance' && <>
        <p className="panel-subtitle">Source trust and sensitivity attached to this recorded event.</p>
        {event.provenance.length === 0 ? <EmptyState title="No provenance linked" description="The official simulator does not include full provenance records on defense-decision events; no source trust is inferred." /> :
          <div className="provenance-list">{event.provenance.map((source) => <div className="provenance-item" key={source.id}><div className="provenance-item__top"><strong>{source.label}</strong><span className={`small-severity small-severity--${source.role}`}>{source.role}</span></div><dl><div><dt>Trust</dt><dd>{source.trustLevel.replaceAll('_', ' ')}</dd></div><div><dt>Sensitivity</dt><dd>{source.sensitivity}</dd></div></dl>{source.detail && <p>{source.detail}</p>}</div>)}</div>}
      </>}
      {tab === 'raw' && <><p className="panel-subtitle">Normalized event record. In API mode free-form content is redacted on the backend before entering your browser.</p><pre className="json-box json-box--large">{JSON.stringify(event, null, 2)}</pre><DownloadButton label="Download event JSON" onClick={() => downloadJSON(`${run.id}-step-${event.index}.json`, event)} /></>}
    </div>
  </Panel>;
}

function DataFlow({ event }: { event: TraceEvent }) {
  const sources = event.provenance.filter((record) => record.role === 'source');
  const target = event.provenance.find((record) => record.role === 'destination');
  if (!target && sources.length === 0) return <p className="muted small-text">No verified source-to-destination flow was logged for this action.</p>;
  return <div className="flow-visual"><div className="flow-node"><strong>{sources[0]?.label || 'Agent action'}</strong><span>{sources[0]?.sensitivity || 'Source'} · {sources[0]?.trustLevel.replaceAll('_', ' ') || 'Unknown'}</span></div><ArrowRight size={18} aria-hidden="true" /><div className="flow-node"><strong>{target?.label || event.tool}</strong><span>{target?.trustLevel.replaceAll('_', ' ') || 'Destination not recorded'}</span></div></div>;
}

function DecisionDistribution({ counts, total }: { counts: Record<Decision, number>; total: number }) {
  const percentages = ALL_DECISIONS.map((name) => total ? (counts[name] / total) * 100 : 0);
  const a = percentages[0], b = a + percentages[1], c = b + percentages[2];
  const gradient = `conic-gradient(var(--allowed) 0% ${a}%, var(--blocked) ${a}% ${b}%, var(--escalated) ${b}% ${c}%, var(--rewritten) ${c}% 100%)`;
  return <div className="distribution"><div className="donut" style={{ background: total > 0 ? gradient : 'var(--border)' }}><div><strong>{total}</strong><span>steps</span></div></div>
    <div className="distribution__legend">{ALL_DECISIONS.map((decision) => <div key={decision} className="distribution__item"><StatusDot status={decision} /><span>{counts[decision]} ({total ? Math.round((counts[decision] / total) * 100) : 0}%)</span></div>)}</div></div>;
}

function RunSummary({ run }: { run: Run }) {
  return <div className="summary-grid"><Panel title="Investigation summary"><p className="summary-lead">{run.summary}</p><div className="summary-details"><Field label="User goal" value={run.userGoal} /><Field label="Scenario" value={<code>{run.scenario}</code>} /><Field label="Domain" value={<DomainLabel domain={run.domain} />} /><Field label="Defense" value={run.defenseVersion} /></div></Panel>
    <Panel title="Recorded outcomes"><OutcomeList run={run} />{run.effectivePolicy && <div className="inspect-section"><h4>Scenario-effective policy</h4><p className="small-text">Profile: {run.effectivePolicy.profile}</p><p className="small-text">Allowed tools: {run.effectivePolicy.allowedTools.length ? run.effectivePolicy.allowedTools.join(' · ') : 'Not recorded'}</p><p className="small-text">Forbidden effects: {run.effectivePolicy.forbiddenEffects.length ? run.effectivePolicy.forbiddenEffects.join(' · ') : 'None declared'}</p><p className="help-copy">Read from the selected scenario definition, not inferred from defense decisions.</p></div>}</Panel>
  </div>;
}
function OutcomeList({ run }: { run: Run }) {
  return <div className="outcome-list"><Field label="Legitimate task completed" value={displayBool(run.taskSuccess)} /><Field label="Attack succeeded" value={displayBool(run.attackSuccess)} /><Field label="Critical violation" value={displayBool(run.criticalViolation)} /><Field label="Data-flow violation" value={displayBool(run.dataFlowViolation)} /><Field label="Defense actions" value={run.events.length} /></div>;
}
function RunArtifacts({ run }: { run: Run }) {
  const exportTrace = () => downloadJSON(`${run.id.toLowerCase()}-trace.json`, run.events);
  return <Panel title="Recorded artifacts"><p className="panel-subtitle">Export the normalized frontend data for this run. Exports are redacted, normalized dashboard data. The original artifacts remain on the local filesystem.</p>
    <div className="artifact-list"><div className="artifact-row"><FileJson size={24} /><div><strong>Full run</strong><p>{run.id.toLowerCase()}.json · Redacted run metadata and normalized trace</p></div><button className="button button--light" type="button" onClick={() => downloadJSON(`${run.id.toLowerCase()}.json`, run)}><Download size={15} /> Download</button></div>
      <div className="artifact-row"><FileJson size={24} /><div><strong>Decision trace</strong><p>{run.id.toLowerCase()}-trace.json · All {run.events.length} recorded actions</p></div><button className="button button--light" type="button" onClick={exportTrace}><Download size={15} /> Download</button></div></div>
  </Panel>;
}
function RunEvaluator({ run }: { run: Run }) {
  return <div className="summary-grid"><Panel title="Evaluation outcome"><OutcomeList run={run} /><p className="help-copy">Outcome fields must come from simulator evaluation, not inferred from individual defense decisions.</p></Panel>
    <Panel title="Interpretation"><p className="summary-lead">{run.attackSuccess === false ? 'The recorded attack did not achieve its objective in this example.' : run.attackSuccess === true ? 'The recorded attack achieved its objective in this example.' : 'This workflow has no attack-success measurement.'}</p><p className="small-text">An action being blocked does not, by itself, establish success for the whole run.</p></Panel></div>;
}
