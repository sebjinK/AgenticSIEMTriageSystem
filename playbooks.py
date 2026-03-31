_PLAYBOOKS = {
    "HIGH": {
        "action": "Disable account and alert SOC",
        "steps": [
            "Immediately disable the IAM user or role",
            "Revoke all active sessions and access keys",
            "Alert SOC team and open an incident ticket",
            "Begin incident response procedure",
            "Preserve CloudTrail logs for forensics",
        ],
    },
    "MEDIUM": {
        "action": "Alert security team and monitor",
        "steps": [
            "Notify security team via email/Slack",
            "Enable enhanced CloudTrail logging for the user",
            "Review all activity for the past 24 hours",
            "Require MFA re-authentication if MFA is absent",
        ],
    },
    "LOW": {
        "action": "Log and monitor",
        "steps": [
            "Log event for baseline tracking",
            "No immediate action required",
            "Review in next scheduled security audit",
        ],
    },
}


def get_playbook_action(severity):
    """Return the one-line recommended action string for a given severity."""
    return _PLAYBOOKS.get(severity, _PLAYBOOKS["LOW"])["action"]


def get_playbook(severity):
    """Return the full playbook dict (action + steps) for a given severity."""
    return _PLAYBOOKS.get(severity, _PLAYBOOKS["LOW"])
