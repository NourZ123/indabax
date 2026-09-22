"""Translate repository policy YAML and official tool registry into read-only UI records.

Policy YAML expresses domain-level rules. Per-scenario allowed_tools vary and should
never be inferred from the domain-wide policy display.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from .redaction import safe_rule_description

log = logging.getLogger(__name__)
# Fallback is only used if the official 'sentinel' Python package is not installed.
# When running from the repository via `uv run`, use the real tool registry instead.
_FALLBACK: dict[str, dict[str, str]] = {
    'enterprise': dict.fromkeys(('email_search', 'email_read', 'document_search', 'document_read', 'wiki_search', 'ticket_read'), 'read')
       | dict.fromkeys(('email_draft', 'email_send', 'ticket_update'), 'write'),
    'finance': dict.fromkeys(('customer_lookup', 'account_summary', 'case_document_read', 'policy_search'), 'read')
       | dict.fromkeys(('case_note_create', 'payment_prepare', 'payment_confirm', 'payment_execute'), 'write'),
    'soc': dict.fromkeys(('alert_search', 'alert_read', 'asset_lookup', 'intel_search'), 'read')
       | dict.fromkeys(('incident_create', 'incident_update', 'remediation_prepare', 'remediation_execute'), 'write'),
}


def _tool_catalog(domain: str) -> list[dict[str, Any]]:
    try:
        from sentinel.tools.registry import registry_for_domain
        registry = registry_for_domain(domain)
        return [
            {'name': t.name, 'description': t.description, 'capabilities': set(t.capabilities), 'consequential': t.consequential}
            for t in registry
        ]
    except ImportError:
        log.warning('sentinel package unavailable: using documented fallback tool names for %s', domain)
        return [
            {'name': name, 'description': 'See the official simulator tool specification.', 'capabilities': {category},
             'consequential': name in {'email_send', 'payment_confirm', 'payment_execute', 'remediation_execute'}}
            for name, category in _FALLBACK.get(domain, {}).items()
        ]


def read_policies(root: Path) -> list[dict[str, Any]]:
    folder = root / 'policies'
    if not folder.is_dir():
        return []
    documents = []
    for path in sorted(folder.glob('*.yaml')):
        if path.is_symlink():
            continue
        try:
            raw = yaml.safe_load(path.read_text(encoding='utf-8'))
        except (OSError, yaml.YAMLError) as exc:
            log.warning('Cannot parse policy %s: %s', path, exc)
            continue
        if not isinstance(raw, dict) or raw.get('domain') not in _FALLBACK:
            continue
        domain = raw['domain']
        rules = raw.get('rules', [])
        rules = rules if isinstance(rules, list) else []
        explicit_confirm = {
            name for r in rules if isinstance(r, dict) and r.get('kind') == 'requires_confirmation'
            and isinstance(r.get('tools'), list) for name in r['tools']
        }
        consequential_rule = any(isinstance(r, dict) and r.get('kind') == 'requires_confirmation' and r.get('tools') == 'consequential' for r in rules)
        tools = []
        for spec in sorted(_tool_catalog(domain), key=lambda t: t['name']):
            name = spec['name']
            caps = spec['capabilities']
            is_read = caps == {'read'}
            is_consequential = spec['consequential']
            category = 'read' if is_read else 'external' if name == 'email_send' else 'consequential' if is_consequential else 'write'
            confirm = 'required' if name in explicit_confirm or (consequential_rule and is_consequential) else 'conditional' if name in {'ticket_update', 'incident_update'} else 'not_required'
            tools.append({
                'name': name,
                'access': 'conditional',  # Actual permission is scenario-specific, not domain-wide.
                'confirmation': confirm,
                'category': category,
                'description': safe_rule_description(spec['description']),
            })
        ui_rules = []
        for item in rules:
            if not isinstance(item, dict) or not isinstance(item.get('id'), str):
                continue
            kind = item.get('kind')
            if kind not in {'tool_permission', 'requires_confirmation', 'data_flow', 'forbidden_effect', 'prerequisite'}:
                continue
            applies: list[str] = []
            if kind == 'prerequisite' and isinstance(item.get('tool'), str):
                applies = [item['tool']]
            elif kind == 'requires_confirmation' and isinstance(item.get('tools'), list):
                applies = [str(t) for t in item['tools']]
            elif kind == 'requires_confirmation' and item.get('tools') == 'consequential':
                applies = [t['name'] for t in tools if t['confirmation'] == 'required']
            elif kind == 'tool_permission':
                applies = [t['name'] for t in tools]
            enforcement = 'Domain-wide rule; exact permissions and requirements depend on the selected scenario.'
            if kind == 'prerequisite':
                enforcement = 'Requires preceding successful tool(s): ' + ', '.join(item.get('requires', []))
            elif kind == 'data_flow':
                enforcement = 'Minimum sensitivity: ' + str(item.get('min_sensitivity', 'confidential'))
            elif kind == 'requires_confirmation':
                enforcement = 'Confirmation required for: ' + (', '.join(item['tools']) if isinstance(item.get('tools'), list) else 'consequential actions')
            ui_rules.append({
                'id': item['id'],
                'name': item['id'].replace('_', ' ').title(),
                'kind': kind,
                'severity': item.get('severity', 'medium'),
                'description': safe_rule_description(item.get('description')),
                'appliesTo': applies,
                'enforcement': enforcement,
            })
        documents.append({
            'id': str(raw.get('id', path.stem)),
            'domain': domain,
            'name': str(raw.get('id', path.stem)).replace('_', ' ').title(),
            'version': str(raw.get('version', 'unknown')),
            'description': safe_rule_description(raw.get('description')) + ' Tool access is conditional on the scenario.',
            'tools': tools,
            'rules': ui_rules,
        })
    return documents
