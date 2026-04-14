"""Policy evaluation engine.

Evaluates tasks against YAML-defined policy rules.
Deny-by-default: if no rule matches, the action is denied.

Per-action evaluation: each TaskAction is evaluated independently against
the rule set. The task-level composite decision uses the most restrictive
effect across all actions (deny > require_approval > allow).
"""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

from jitauth.config.settings import get_settings
from jitauth.core.models import Task, TaskAction

logger = logging.getLogger(__name__)

_rules_cache: list[dict] | None = None

# Effect severity ordering: higher index = more restrictive
_EFFECT_SEVERITY = {
    "allow": 0,
    "allow_reduced": 1,
    "require_simulation": 2,
    "require_approval": 3,
    "quarantine": 4,
    "deny": 5,
}


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


def evaluate_action(action: TaskAction, task: Task) -> dict:
    """Evaluate a single action against loaded policy rules.

    Returns a decision dict:
        {
            "rule_name": str,
            "effect": str,
            "reason": str | None,
            "scope": dict | None,
            "system": str,
            "action": str,
            "action_class": str,
        }
    """
    rules = _load_rules()

    for rule in rules:
        if _matches_action(rule, action, task):
            return {
                "rule_name": rule["name"],
                "effect": rule["effect"],
                "reason": rule.get("reason"),
                "scope": rule.get("scope"),
                "system": action.system,
                "action": action.action,
                "action_class": action.action_class.value,
            }

    return {
        "rule_name": "default_deny",
        "effect": "deny",
        "reason": "No matching policy rule — denied by default",
        "system": action.system,
        "action": action.action,
        "action_class": action.action_class.value,
    }


def evaluate(task: Task) -> dict:
    """Evaluate a task by independently evaluating each action.

    Returns a composite decision dict:
        {
            "rule_name": str,           # rule that produced the most restrictive effect
            "effect": str,              # most restrictive effect across all actions
            "reason": str | None,
            "scope": dict | None,
            "action_decisions": list,   # per-action decision dicts
        }

    The composite effect is the most restrictive across all actions:
    deny > quarantine > require_approval > require_simulation > allow_reduced > allow
    """
    if not task.actions:
        return {
            "rule_name": "default_deny",
            "effect": "deny",
            "reason": "Task has no actions",
            "action_decisions": [],
        }

    action_decisions = [evaluate_action(a, task) for a in task.actions]

    # Find the most restrictive decision
    most_restrictive = max(
        action_decisions,
        key=lambda d: _EFFECT_SEVERITY.get(d["effect"], 5),
    )

    return {
        "rule_name": most_restrictive["rule_name"],
        "effect": most_restrictive["effect"],
        "reason": most_restrictive["reason"],
        "scope": most_restrictive.get("scope"),
        "action_decisions": action_decisions,
    }


def _matches_action(rule: dict, action: TaskAction, task: Task) -> bool:
    """Check if a rule's match conditions apply to a single action."""
    from jitauth.policy.risk import classify_action_risk

    match = rule.get("match", {})

    # Match on risk tier — use the action's own risk tier, not the task aggregate
    if "risk_tier" in match:
        allowed_tiers = match["risk_tier"]
        if isinstance(allowed_tiers, str):
            allowed_tiers = [allowed_tiers]
        action_risk = classify_action_risk(action, task)
        if action_risk.value not in allowed_tiers:
            return False

    # Match on system
    if "system" in match:
        if match["system"] != action.system:
            return False

    # Match on action name
    if "action" in match:
        target_actions = match["action"]
        if isinstance(target_actions, str):
            target_actions = [target_actions]
        if action.action not in target_actions:
            return False

    # Match on action class
    if "action_class" in match:
        target_classes = match["action_class"]
        if isinstance(target_classes, str):
            target_classes = [target_classes]
        if action.action_class.value not in target_classes:
            return False

    # Match on runtime trust tier (task-level property)
    if "runtime_trust_tier" in match:
        allowed = match["runtime_trust_tier"]
        if isinstance(allowed, str):
            allowed = [allowed]
        if task.runtime_trust_tier not in allowed:
            return False

    return True
