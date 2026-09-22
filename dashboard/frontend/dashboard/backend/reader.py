"""Read-only adapter: official SENTINEL JSONL events, .summary.json outcomes and scorecards.

The official simulator logs DEFENSE_DECISION with risk/confidence/reason codes but
NOT the defense's metadata. It uses a logical clock, so timestamp differences do
NOT measure real latency. Per-step latency is read only from evaluator summaries.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .redaction import REDACTED, safe_action, safe_arguments, safe_reason_codes

log = logging.getLogger(__name__)
_VALID_DECISIONS = {'allow', 'block', 'escalate', 'rewrite'}
_VALID_DOMAINS = {'enterprise', 'finance', 'soc'}


def _load_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file() or path.is_symlink():
        return None
    try:
        parsed = json.loads(path.read_text(encoding='utf-8'))
        return parsed if isinstance(parsed, dict) else None
    except (ValueError, OSError) as exc:
        log.warning('Cannot read %s: %s', path, exc)
        return None


def _load_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    if path.is_symlink() or path.stat().st_size > 32_000_000:
        raise ValueError('Run artifact is a symlink or exceeds 32 MB')
    with path.open(encoding='utf-8') as handle:
        for lineno, line in enumerate(handle, 1):
            if not line.strip():
                continue
            obj = json.loads(line)
            if not isinstance(obj, dict) or not isinstance(obj.get('payload'), dict):
                raise ValueError(f'invalid event at line {lineno}')
            events.append(obj)
            if len(events) > 10_000:
                raise ValueError('Run artifact exceeds 10,000 events')
    return events


def _as_bool(src: dict[str, Any] | None, name: str) -> bool | None:
    if src is None:
        return None
    value = src.get(name)
    return value if isinstance(value, bool) else None


def _outcome(summary: dict[str, Any] | None) -> str:
    if summary is None:
        return 'not_evaluated'
    if summary.get('attack_present') is True:
        if summary.get('attack_success') is True:
            return 'attack_succeeded'
        if summary.get('attack_success') is False:
            # Attack failure does not necessarily mean an action was blocked.
            return 'attack_failed'
        return 'not_evaluated'
    if summary.get('task_success') is True:
        return 'task_completed'
    if summary.get('task_success') is False:
        return 'task_incomplete'
    return 'not_evaluated'


def normalize_run(path: Path, scenarios: dict[str, dict[str, Any]]) -> dict[str, Any]:
    events = _load_events(path)
    summary = _load_json(path.with_name(path.stem + '.summary.json'))
    scenario_id = summary.get('scenario_id') if summary else None
    if not isinstance(scenario_id, str):
        # Official run ID begins with scenario_id; use prefix only as a last resort.
        scenario_id = next((sid for sid in scenarios if path.stem.startswith(sid + '-')), '')
    scenario = scenarios.get(scenario_id, {})
    domain = summary.get('domain') if summary else scenario.get('domain')
    if domain not in _VALID_DOMAINS:
        domain = scenario.get('domain')
        if domain not in _VALID_DOMAINS:
            domain = 'unknown'
    safe_scenario = scenario_id or 'unknown_scenario'

    # The evaluator's DecisionRecord has the actual defense API latency in ms.
    measured = {}
    if summary and isinstance(summary.get('decisions'), list):
        for decision in summary['decisions']:
            if isinstance(decision, dict) and isinstance(decision.get('step_id'), int):
                measured[decision['step_id']] = decision.get('latency_ms')

    # Only these events are agent-action decisions. USER_MESSAGE, retrieval events,
    # and evaluator events are evidence attached to steps, not extra defense actions.
    result_by_step: dict[int, str] = {}
    for ev in events:
        sid, typ, payload = ev.get('step_id'), ev.get('type'), ev.get('payload', {})
        if not isinstance(sid, int):
            continue
        if typ in ('tool_result', 'retrieval_result'):
            result_by_step[sid] = 'Tool succeeded' if payload.get('succeeded') is True else 'Tool failed'
        elif typ == 'memory_write':
            result_by_step[sid] = 'Memory write recorded (content redacted)'
        elif typ == 'model_output':
            result_by_step[sid] = 'Agent response recorded (content redacted)'
        elif typ == 'human_confirmation':
            result_by_step[sid] = 'Human approved' if payload.get('approved') is True else 'Human denied'

    normalized = []
    for ev in events:
        if ev.get('type') != 'defense_decision':
            continue
        payload = ev['payload']
        step = ev.get('step_id')
        if not isinstance(step, int):
            continue
        raw_action = payload.get('action') if isinstance(payload.get('action'), dict) else {}
        tool = raw_action.get('tool') or raw_action.get('type') or 'unknown'
        decision = payload.get('decision')
        if decision not in _VALID_DECISIONS:
            continue
        tool = tool if isinstance(tool, str) else 'unknown'
        safe_tool = tool[:80]
        milliseconds = measured.get(step)
        if not isinstance(milliseconds, (int, float)) or isinstance(milliseconds, bool):
            milliseconds = None
        codes = safe_reason_codes(payload.get('reason_codes'))
        # Defense explanations can interpolate attacker-authored text, so do not echo
        # arbitrary explanations; use recorded structured reason codes instead.
        explanation = ', '.join(codes).replace('_', ' ').capitalize() if codes else 'No structured reason recorded'
        rewritten = safe_action(payload.get('rewritten_action'))
        normalized.append({
            'id': str(ev.get('event_id', f'{path.stem}-{step}'))[:150],
            'index': len(normalized) + 1,
            'stepId': step,
            'occurredAt': ev.get('timestamp') if isinstance(ev.get('timestamp'), str) else datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat(),
            'description': f'Proposed {safe_tool}',
            'tool': safe_tool,
            'decision': decision,
            'durationMs': round(milliseconds, 3) if milliseconds is not None else None,
            'riskScore': payload.get('risk_score') if isinstance(payload.get('risk_score'), (int, float)) and not isinstance(payload.get('risk_score'), bool) else None,
            'confidence': payload.get('confidence') if isinstance(payload.get('confidence'), (int, float)) and not isinstance(payload.get('confidence'), bool) else None,
            'explanation': explanation,
            'reasonCodes': codes,
            'arguments': safe_arguments(raw_action.get('arguments')) if raw_action.get('type') == 'tool_call' else ({'content': REDACTED} if raw_action.get('content') is not None else {}),
            'rewrittenAction': rewritten,
            'result': result_by_step.get(step),
            'signals': {},  # Official simulator does not persist DefenseDecision.metadata.
            'provenance': [],  # Decision events do not include provenance records or trust labels.
        })

    started = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat()
    title = scenario.get('title') if isinstance(scenario.get('title'), str) else safe_scenario.replace('_', ' ').capitalize()
    defense = summary.get('defense') if summary else None
    return {
        'id': path.stem,
        'domain': domain,
        'scenario': safe_scenario,
        'title': title,
        'createdAt': started,  # Actual artifact save time; event clock is simulated.
        'model': 'Not recorded',  # Run artifact does not record model identity.
        'defenseVersion': str(defense) if defense else 'Not recorded',
        'effectivePolicy': {
            'profile': str(scenario.get('policy_profile') or 'Not recorded'),
            'allowedTools': scenario.get('allowed_tools', []),
            'forbiddenEffects': scenario.get('forbidden_effects', []),
        } if scenario else None,
        'durationMs': None,  # No wall-clock run duration in official artifacts.
        'userGoal': REDACTED if any(ev.get('type') == 'user_message' for ev in events) else 'Not recorded',
        'summary': 'Recorded SENTINEL run. Review the action trace and measured evaluator outcome where available.',
        'outcome': _outcome(summary),
        'taskSuccess': _as_bool(summary, 'task_success'),
        'attackSuccess': _as_bool(summary, 'attack_success') if summary and summary.get('attack_present') else None,
        'criticalViolation': _as_bool(summary, 'critical_violation'),
        'dataFlowViolation': _as_bool(summary, 'data_flow_violation'),
        'events': normalized,
    }


def _scenario_index(root: Path) -> dict[str, dict[str, Any]]:
    try:
        import yaml
    except ImportError:
        return {}
    found: dict[str, dict[str, Any]] = {}
    directory = root / 'scenarios'
    if not directory.is_dir():
        return found
    for path in directory.glob('**/*.yaml'):
        if path.is_symlink():
            continue
        try:
            src = yaml.safe_load(path.read_text(encoding='utf-8'))
            if isinstance(src, dict) and isinstance(src.get('id'), str):
                found[src['id']] = {
                    'title': str(src.get('title') or src['id']), 'domain': src.get('domain'),
                    'policy_profile': str(src.get('policy_profile') or ''),
                    'allowed_tools': [x for x in src.get('allowed_tools', []) if isinstance(x, str)][:60],
                    'forbidden_effects': [x for x in src.get('forbidden_effects', []) if isinstance(x, str)][:60],
                }
        except (OSError, ValueError, yaml.YAMLError) as exc:
            log.warning('Cannot inspect scenario %s: %s', path, exc)
    return found


def read_runs(root: Path, artifacts: Path) -> list[dict[str, Any]]:
    if not artifacts.is_dir():
        return []
    scenarios = _scenario_index(root)
    results = []
    for path in artifacts.glob('*/*.jsonl'):
        # Prevent a linked folder within artifacts from leaking files elsewhere.
        if path.is_symlink() or not path.resolve().is_relative_to(artifacts.resolve()):
            continue
        try:
            results.append(normalize_run(path, scenarios))
        except (OSError, ValueError, UnicodeError) as exc:
            log.warning('Skipping malformed run artifact %s: %s', path, exc)
    return sorted(results, key=lambda r: r['createdAt'], reverse=True)


def read_experiments(artifacts: Path) -> list[dict[str, Any]]:
    scorecards = artifacts / 'scorecards'
    if not scorecards.is_dir() or scorecards.is_symlink():
        return []
    experiments = []
    for path in sorted(scorecards.glob('*.json')):
        raw = _load_json(path)
        if not raw:
            continue
        metric = raw.get('metrics')
        if not isinstance(metric, dict):
            continue
        defense = str(raw.get('defense', path.stem))
        baseline = {'allow_all', 'deny_sensitive', 'keyword', 'heuristic_risk', 'provenance'}
        name_lower = defense.lower() + ' ' + path.stem.lower()
        kind = 'baseline' if defense in baseline else 'ablation' if 'ablation' in name_lower or 'no_' in name_lower else 'full'
        def ratio(name: str) -> float | None:
            value = metric.get(name)
            return value if isinstance(value, (int, float)) and not isinstance(value, bool) else None
        experiments.append({
            'id': path.stem,
            'name': defense + ' · ' + str(raw.get('split', 'evaluation')),
            'kind': kind,
            'domain': 'all',
            'totalScenarios': int(raw.get('scenario_count', metric.get('scenario_count', 0))),
            'legitimateTaskRate': ratio('btu'),
            'attackSuccessRate': ratio('asr'),
            'criticalViolationRate': ratio('cvr'),
            'falseBlockRate': ratio('fbr'),
            'unnecessaryEscalationRate': ratio('uer'),
            'medianLatencyMs': ratio('latency_median_ms'),
        })
    return experiments
