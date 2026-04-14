"""Risk classification for tasks.

Maps action classes to risk tiers per spec section 13.
"""

from __future__ import annotations

from jitauth.core.models import ActionClass, RiskTier, Task

# Action class → base risk tier mapping
_ACTION_RISK: dict[ActionClass, RiskTier] = {
    ActionClass.read: RiskTier.tier_1,
    ActionClass.write: RiskTier.tier_2,
    ActionClass.send: RiskTier.tier_3,
    ActionClass.publish: RiskTier.tier_3,
    ActionClass.delete: RiskTier.tier_4,
    ActionClass.execute: RiskTier.tier_4,
}

# Systems that lower read risk to tier_0
_HARMLESS_READ_SYSTEMS = {"public_docs", "help", "documentation"}


def classify_risk(task: Task) -> tuple[RiskTier, list[str]]:
    """Classify a task's risk tier based on its actions.

    Returns (risk_tier, list_of_action_class_strings).
    The overall risk tier is the highest tier among all actions.
    """
    if not task.actions:
        return RiskTier.tier_0, []

    highest = RiskTier.tier_0
    action_classes = []

    for action in task.actions:
        ac = action.action_class
        action_classes.append(ac.value)

        tier = _ACTION_RISK.get(ac, RiskTier.tier_1)

        # Downgrade harmless reads
        if ac == ActionClass.read and action.system in _HARMLESS_READ_SYSTEMS:
            tier = RiskTier.tier_0

        # Upgrade if task allows destructive but action is write
        if task.allow_destructive and ac == ActionClass.write:
            tier = RiskTier.tier_3

        if tier.value > highest.value:
            highest = tier

    return highest, action_classes
