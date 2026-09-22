export type Decision = 'allow' | 'block' | 'escalate' | 'rewrite';
export type DisplayStatus = Decision | 'completed' | 'online' | 'offline';
export type Domain = 'enterprise' | 'finance' | 'soc';
export type RunOutcome = 'attack_blocked' | 'attack_succeeded' | 'task_completed' | 'task_incomplete';
export type Severity = 'low' | 'medium' | 'high' | 'critical';
export type SignalName = 'Information flow' | 'Injection' | 'Goal alignment' | 'Policy' | 'History';

export interface ProvenanceRecord {
  id: string;
  label: string;
  trustLevel: 'system_policy' | 'authenticated_user' | 'trusted_internal' | 'untrusted_internal' | 'untrusted_external' | 'adversary_controlled';
  sensitivity: 'public' | 'internal' | 'confidential' | 'restricted';
  role: 'source' | 'destination' | 'context';
  detail?: string;
}

export interface TraceEvent {
  id: string;
  index: number;
  occurredAt: string;
  description: string;
  tool: string;
  decision: Decision;
  durationMs: number | null;
  riskScore: number | null;
  confidence: number | null;
  explanation: string;
  reasonCodes: string[];
  arguments: Record<string, unknown>;
  rewrittenAction?: Record<string, unknown>;
  result?: string;
  signals: Partial<Record<SignalName, number>>;
  provenance: ProvenanceRecord[];
}

export interface Run {
  id: string;
  domain: Domain;
  scenario: string;
  title: string;
  createdAt: string;
  model: string;
  defenseVersion: string;
  durationMs: number;
  userGoal: string;
  summary: string;
  outcome: RunOutcome;
  taskSuccess: boolean | null;
  attackSuccess: boolean | null;
  criticalViolation: boolean | null;
  dataFlowViolation: boolean | null;
  events: TraceEvent[];
}

export interface PolicyTool {
  name: string;
  access: 'allowed' | 'conditional' | 'not_allowed';
  confirmation: 'required' | 'conditional' | 'not_required';
  category: 'read' | 'write' | 'external' | 'consequential';
  description: string;
}

export interface PolicyRule {
  id: string;
  name: string;
  kind: 'tool_permission' | 'requires_confirmation' | 'data_flow' | 'forbidden_effect' | 'prerequisite';
  severity: Severity;
  description: string;
  appliesTo: string[];
  enforcement: string;
}

export interface PolicyDocument {
  id: string;
  domain: Domain;
  name: string;
  version: string;
  description: string;
  tools: PolicyTool[];
  rules: PolicyRule[];
}

export interface Experiment {
  id: string;
  name: string;
  kind: 'full' | 'baseline' | 'ablation';
  domain: Domain | 'all';
  totalScenarios: number;
  legitimateTaskRate: number | null;
  attackSuccessRate: number | null;
  criticalViolationRate: number | null;
  falseBlockRate: number | null;
  unnecessaryEscalationRate: number | null;
  averageLatencyMs: number | null;
}

export interface DashboardData {
  runs: Run[];
  policies: PolicyDocument[];
  experiments: Experiment[];
}

export type TimeRange = '24h' | '7d' | '30d' | 'all';
