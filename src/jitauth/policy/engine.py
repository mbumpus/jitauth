"""Policy evaluation engine.

Evaluates tasks against YAML-defined policy rules.
Deny-by-default: if no rule matches, the task is denied.
"""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

from jitauth.config.settings import get_settings
from jitauth.core.models import Task

logger = logging.getLogger(__name__)

_rules_cache: list[dict] | None = None


def _load_rules() -> list[dict]:
    """Load policy rules from YAML files in the policy directory."""
    global _rules_cache
    if _rules_cache is not None:
        return _rules_cache

    settings = get_settings()
    policy_dir = Path(settings.policy_dir)
    rules = []

    if not policy_dir.exists():
        logger.warning("Policy directory '%s' not found, using deny-all default", policy_dir)
        _rules_cache = []
        return _rules_cache

    for f in sorted(policy_dir.glob("*.yaml")):
        try:
            with open(f) as fh:
                doc = yaml.safe_load(fh)
            if doc and "rules" in doc:
                for rule in doc["rules"]:
                    rule.setdefault("priority", 100)
                    rules.append(rule)
        except Exception as e:
            logger.error("Failed to load policy file %s: %s", f, e)

    rules.sort(key=lambda r: r.get("priority", 100))
    _rules_cache = rules
    return _rules_cache


def reload_rules() -> None:
    """Force reload of policy rules."""
    global _rules_cache
    _rules_cache = None


def evaluate(task: Task) -> dict:
    """Evaluate a task against loaded policy rules.

    Returns a decision dict:
        {
            "rule_name": str,
            "effect": str,  # allow, allow_reduced, require_approval, deny, quarantine
            "reason": str | None,
            "scope": dict | None,
        }
    """
    rules = _load_rules()

    for rule in rules:
        if _matches(rule, task):
            return {
                "rule_name": rule["name"],
                "effect": rule["effect"],
                "reason": rule.get("reason"),
                "scope": rule.get("scope"),
            }

    # Deny by default — the most important line in this file
    return {
        "rule_name": "default_deny",
        "effect": "deny",
        "reason": "No matching policy rule — denied by default",
    }


def _matches(rule: dict, task: Task) -> bool:
    """Check if a rule's match conditions apply to a task."""
    match = rule.get("match", {})

    # Match on risk tier
    if "risk_tier" in match:
        allowed_tiers = match["risk_tier"]
        if isinstance(allowed_tiers, str):
            allowed_tiers = [allowed_tiers]
        if task.risk_tier and task.risk_tier.value not in allowed_tiers:
            return False

    # Match on system
    if "system" in match:
        task_systems = {a.system for a in task.actions}
        if match["system"] not in task_systems:
            return False

    # Match on action
    if "action" in match:
        task_actions = {a.action for a in task.actions}
        target_actions = match["action"]
        if isinstance(target_actions, str):
            target_actions = [target_actions]
        if not task_actions.intersection(target_actions):
            return False

    # Match on action class
    if "action_class" in match:
        task_classes = {a.action_class.value for a in task.actions}
        target_classes = match["action_class"]
        if isinstance(target_classes, str):
            target_classes = [target_classes]
        if not task_classes.intersection(target_classes):
            return False

    # Match on runtime trust tier
    if "runtime_trust_tier" in match:
        allowed = match["runtime_trust_tier"]
        if isinstance(allowed, str):
            allowed = [allowed]
        if task.runtime_trust_tier not in allowed:
            return False

    return True
