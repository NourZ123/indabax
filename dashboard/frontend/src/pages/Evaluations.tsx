import { useMemo, useState } from 'react';
import { ArrowDownRight, ArrowUpRight, Info } from 'lucide-react';
import { asPercent, DownloadButton, EmptyState, MetricCard, Panel, SectionHeading } from '../components/Common';
import { downloadCSV } from '../services/api';
import type { Experiment } from '../types/sentinel';

type ExperimentFilter = 'all' | 'baseline' | 'ablation';

export function EvaluationsPage({ experiments }: { experiments: Experiment[] }) {
  const [filter, setFilter] = useState<ExperimentFilter>('all');
  const full = experiments.find((experiment) => experiment.kind === 'full');
  const filtered = useMemo(() => experiments.filter((experiment) => filter === 'all' || experiment.kind === filter || experiment.kind === 'full'), [experiments, filter]);
  return <div className="page-stack">
    <SectionHeading title="Evaluations" description="Compare defense effectiveness, task utility, baseline behavior and ablations."
      action={<DownloadButton label="Export comparison" onClick={() => downloadCSV('sentinel-evaluations.csv',
        ['Experiment', 'Kind', 'Scenarios', 'Legitimate task rate', 'Attack success rate', 'Critical violation rate', 'False block rate', 'Unnecessary escalation rate', 'Median latency (ms)'],
        filtered.map((item) => [item.name, item.kind, item.totalScenarios, item.legitimateTaskRate, item.attackSuccessRate, item.criticalViolationRate, item.falseBlockRate, item.unnecessaryEscalationRate, item.medianLatencyMs]))} />} />
    <div className="notice notice--info"><Info size={16} aria-hidden="true" /><div><strong>Keep evaluations and risk scores separate.</strong> The figures below are aggregate experiment results supplied by the data source; a per-action risk score is not an observed attack probability.</div></div>
    <div className="metrics-grid metrics-grid--four">
      <MetricCard label="Legitimate task utility" value={asPercent(full?.legitimateTaskRate)} description="Task completion across evaluated scenarios" />
      <MetricCard label="Attack success" value={asPercent(full?.attackSuccessRate)} color="var(--blocked)" description="Lower is preferable for security" />
      <MetricCard label="Critical violations" value={asPercent(full?.criticalViolationRate)} color="var(--blocked)" description="Measured by the evaluator" />
      <MetricCard label="False block rate" value={asPercent(full?.falseBlockRate)} description="Legitimate actions blocked" />
    </div>
    <Panel title="Experiment comparison" action={<div className="segmented-control" role="group" aria-label="Experiment type filter">
      {(['all', 'baseline', 'ablation'] as ExperimentFilter[]).map((value) => <button key={value} type="button" onClick={() => setFilter(value)} aria-pressed={filter === value} className={filter === value ? 'segmented-control__active' : ''}>{value === 'all' ? 'All experiments' : value === 'baseline' ? 'Baselines' : 'Ablations'}</button>)}
    </div>}>
      <p className="panel-subtitle">Comparisons are meaningful only when models, scenarios and evaluation settings are consistent.</p>
      {filtered.length === 0 ? <EmptyState title="No experiments" description="No experiments match the selected filter." /> : <div className="table-scroll"><table className="data-table evaluation-table">
        <thead><tr><th>Experiment</th><th>Kind</th><th>Scenarios</th><th>Task utility</th><th>Attack success</th><th>Critical violations</th><th>False blocks</th><th>Escalation</th><th>Median latency</th></tr></thead>
        <tbody>{filtered.map((item) => <tr key={item.id} className={item.kind === 'full' ? 'evaluation-row--primary' : ''}>
          <td><strong>{item.name}</strong></td><td><span className="type-label">{item.kind}</span></td><td>{item.totalScenarios}</td>
          <td>{asPercent(item.legitimateTaskRate)}</td><td className={item.attackSuccessRate !== null && item.attackSuccessRate <= 0.15 ? 'cell-good' : ''}>{asPercent(item.attackSuccessRate)}</td>
          <td>{asPercent(item.criticalViolationRate)}</td><td>{asPercent(item.falseBlockRate)}</td><td>{asPercent(item.unnecessaryEscalationRate)}</td><td>{item.medianLatencyMs === null ? '—' : `${item.medianLatencyMs} ms`}</td>
        </tr>)}</tbody>
      </table></div>}
    </Panel>
    <div className="evaluation-grid">
      <Panel title="Attack success vs. task utility"><p className="panel-subtitle">Two outcomes that should be interpreted together.</p>
        <div className="comparison-bars">{filtered.map((item) => <div key={item.id} className="comparison-item"><div className="comparison-item__title"><strong>{item.name}</strong><span>{item.kind}</span></div>
          <div className="comparison-item__line"><span>Task utility</span><div className="comparison-track"><i className="comparison-fill comparison-fill--good" style={{ width: `${(item.legitimateTaskRate ?? 0) * 100}%` }} /></div><strong>{asPercent(item.legitimateTaskRate)}</strong></div>
          <div className="comparison-item__line"><span>Attack success</span><div className="comparison-track"><i className="comparison-fill comparison-fill--bad" style={{ width: `${(item.attackSuccessRate ?? 0) * 100}%` }} /></div><strong>{asPercent(item.attackSuccessRate)}</strong></div>
        </div>)}</div>
      </Panel>
      <Panel title="Ablation insights"><p className="panel-subtitle">Understand how each protection layer changes the observed results.</p>
        <div className="ablation-list">{experiments.filter((item) => item.kind === 'ablation').map((item) => {
          const delta = item.attackSuccessRate === null || full?.attackSuccessRate === null || full?.attackSuccessRate === undefined ? null : item.attackSuccessRate - full.attackSuccessRate;
          return <div className="ablation-item" key={item.id}><div><strong>{item.name}</strong><span>Compared with the full defense</span></div>
            {delta === null ? <span>—</span> : <span className={delta > 0 ? 'delta--bad' : 'delta--good'}>{delta > 0 ? <ArrowUpRight size={15} /> : <ArrowDownRight size={15} />}{delta > 0 ? '+' : ''}{Math.round(delta * 100)} pp attack success</span>}
          </div>;
        })}</div><p className="help-copy">Ablation results must come from separate runs. Turning off a feature flag alone does not constitute an evaluation.</p>
      </Panel>
    </div>
  </div>;
}
