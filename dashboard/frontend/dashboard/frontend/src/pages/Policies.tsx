import { useMemo, useState } from 'react';
import { ArrowRight, Info, LockKeyhole, Search, ShieldCheck } from 'lucide-react';
import { Link } from 'react-router-dom';
import { DomainLabel, EmptyState, Field, Panel, SectionHeading, StatusDot } from '../components/Common';
import type { Domain, PolicyDocument, PolicyRule, Run } from '../types/sentinel';

const RULE_SIGNAL_HINTS: Record<PolicyRule['kind'], string[]> = {
  tool_permission: ['POLICY_TOOL_NOT_ALLOWED'], requires_confirmation: ['MISSING_CONFIRMATION'],
  data_flow: ['SENSITIVE_DATA_FLOW', 'SECRET_TO_EXTERNAL_SINK'], forbidden_effect: ['AUTHORITY_MISMATCH'],
  prerequisite: ['POLICY_PREREQUISITE_MISSING'],
};

export function PoliciesPage({ policies, runs }: { policies: PolicyDocument[]; runs: Run[] }) {
  const [domain, setDomain] = useState<Domain>('enterprise');
  const [toolSearch, setToolSearch] = useState('');
  const [selectedRuleId, setSelectedRuleId] = useState<string | null>(null);
  const policy = policies.find((item) => item.domain === domain);
  const rule = policy?.rules.find((item) => item.id === selectedRuleId) ?? policy?.rules[0];
  const related = useMemo(() => rule ? runs.filter((run) => run.domain === domain).flatMap((run) => run.events.filter((event) => event.reasonCodes.some((code) => RULE_SIGNAL_HINTS[rule.kind].includes(code))).map((event) => ({ event, run }))) : [], [domain, rule, runs]);
  if (!policy) return <EmptyState title="No policies available" description="No document was supplied for this domain." />;
  const filteredTools = policy.tools.filter((tool) => `${tool.name} ${tool.description} ${tool.category}`.toLowerCase().includes(toolSearch.toLowerCase()));
  return <div className="page-stack">
    <SectionHeading title="Policies" description="Inspect tool permissions, security rules and their enforcement context." action={<div className="policy-mode"><LockKeyhole size={15} /> Read-only</div>} />
    <div className="policy-domain-switch" role="group" aria-label="Select policy environment">{(['enterprise', 'finance', 'soc'] as Domain[]).map((name) => <button key={name} className={domain === name ? 'policy-domain--active' : ''} type="button" onClick={() => { setDomain(name); setSelectedRuleId(null); setToolSearch(''); }}><DomainLabel domain={name} /></button>)}</div>
    <div className="policy-summary-grid">
      <Panel title="Domain policy"><div className="policy-headline"><div className="policy-icon"><ShieldCheck size={23} /></div><div><h3>{policy.name}</h3><p>{policy.description}</p></div></div><div className="policy-meta-grid"><Field label="Policy ID" value={<code>{policy.id}</code>} /><Field label="Version" value={policy.version} /><Field label="Tools listed" value={policy.tools.length} /><Field label="Rules listed" value={policy.rules.length} /></div></Panel>
      <Panel title="Enforcement model"><div className="enforcement-summary"><div><StatusDot status="online" label="Read-only inspection" /><p>Each candidate action is checked against the active scenario's exposed policy context. Domain policy definitions do not reveal the scenario-specific allowed tools. Inspect each run separately.</p></div><div className="enforcement-divider" /><div><strong>Safety controls</strong><span>Tool permission · Confirmation · Data flow · Prerequisites · Forbidden effects</span></div></div></Panel>
    </div>
    <Panel title="Tool permissions" action={<div className="inline-search inline-search--small"><Search size={15} aria-hidden="true" /><input value={toolSearch} onChange={(e) => setToolSearch(e.target.value)} aria-label="Search policy tools" placeholder="Search tools..." /></div>}>
      {filteredTools.length === 0 ? <EmptyState title="No matching tools" description="Try a different tool name or category." /> : <div className="table-scroll"><table className="data-table"><thead><tr><th>Tool</th><th>Category</th><th>Permission</th><th>Confirmation</th><th>Description</th></tr></thead>
        <tbody>{filteredTools.map((tool) => <tr key={tool.name}><td className="mono table-primary">{tool.name}</td><td><span className="type-label">{tool.category}</span></td>
          <td><StatusDot status={tool.access === 'not_allowed' ? 'block' : tool.access === 'conditional' ? 'escalate' : 'allow'} label={tool.access === 'not_allowed' ? 'Not allowed' : tool.access === 'conditional' ? 'Conditional' : 'Allowed'} /></td>
          <td>{tool.confirmation === 'required' ? <StatusDot status="escalate" label="Required" /> : tool.confirmation === 'conditional' ? 'Conditional' : <span className="muted">Not required</span>}</td><td className="tool-description">{tool.description}</td></tr>)}</tbody>
      </table></div>}
    </Panel>
    <div className="policy-rules-grid">
      <Panel title="Security rules"><p className="panel-subtitle">Select a rule to inspect its purpose and affected tools.</p><div className="rule-list">{policy.rules.map((item) => <button type="button" key={item.id} className={`rule-list__item ${rule?.id === item.id ? 'rule-list__item--active' : ''}`} onClick={() => setSelectedRuleId(item.id)}>
        <div><strong>{item.name}</strong><span>{item.id} · {item.kind.replaceAll('_', ' ')}</span></div><ArrowRight size={16} /></button>)}</div></Panel>
      <Panel title="Rule inspector">{rule ? <div className="rule-inspector"><span className="eyebrow">{rule.id} · {rule.kind.replaceAll('_', ' ')}</span><h3>{rule.name}</h3><div className="rule-severity"><span className={`severity-marker severity-marker--${rule.severity}`} />{rule.severity} severity</div>
        <p>{rule.description}</p><div className="inspect-section"><h4>Applies to</h4><div className="tool-tags">{rule.appliesTo.map((tool) => <code key={tool}>{tool}</code>)}</div></div>
        <div className="inspect-section"><h4>Enforcement</h4><p className="small-text">{rule.enforcement}</p></div>
        <div className="inspect-section"><h4>Related decision signals</h4><p className="help-copy">Matched by reason-code category; without explicit rule IDs in a trace, these are not verified rule-specific enforcement events.</p>
          {related.length === 0 ? <p className="muted">No matching reason codes appear in the available recorded runs.</p> : <div className="related-events">{related.slice(0, 4).map(({ run, event }) => <Link to={`/runs/${run.id}`} key={event.id}><span><strong>{run.id}</strong> · {event.tool}</span><StatusDot status={event.decision} /></Link>)}</div>}
        </div></div> : <EmptyState title="Select a rule" description="Choose a security rule from the list." />}</Panel>
    </div>
    <div className="notice notice--info"><Info size={17} /><span>Actual scenarios may expose different allowed tools and confirmation requirements. Inspect an individual run to see the policy context associated with its decisions.</span></div>
  </div>;
}
