"""
Response Orchestration Agent
Analyzes attack paths and incidents, generates prioritized containment/remediation
actions with trust scores, confidence levels, and human-readable explanations.
"""

from datetime import datetime

# ─── Response Action Templates ────────────────────────────────────────────────
ACTION_TEMPLATES = {
    "isolate_host": {
        "category": "containment",
        "icon": "shield-off",
        "risk": "medium",
        "description_template": "Isolate host {hostname} from network to prevent further lateral movement",
        "details_template": "Network isolation will disconnect {hostname} from all network segments while maintaining EDR agent connectivity for remote investigation. This is reversible.",
        "automated": True,
        "estimated_time": "< 1 minute",
    },
    "block_ip": {
        "category": "containment",
        "icon": "ban",
        "risk": "low",
        "description_template": "Block IP {ip} at perimeter firewall",
        "details_template": "Add {ip} ({geo}) to the global block list across all firewall appliances. This will terminate existing sessions and prevent new connections.",
        "automated": True,
        "estimated_time": "< 1 minute",
    },
    "disable_account": {
        "category": "containment",
        "icon": "user-x",
        "risk": "high",
        "description_template": "Disable compromised account: {user}",
        "details_template": "Immediately disable {user} in Active Directory/Okta, revoke all active sessions and tokens. User will need password reset and MFA re-enrollment.",
        "automated": True,
        "estimated_time": "< 1 minute",
    },
    "reset_credentials": {
        "category": "remediation",
        "icon": "key",
        "risk": "medium",
        "description_template": "Force credential reset for {user}",
        "details_template": "Invalidate current password and all tokens for {user}. Force password change on next login with new MFA enrollment.",
        "automated": True,
        "estimated_time": "2-5 minutes",
    },
    "kill_process": {
        "category": "containment",
        "icon": "x-circle",
        "risk": "medium",
        "description_template": "Terminate malicious process on {hostname}",
        "details_template": "Remotely terminate the identified malicious process tree on {hostname} via EDR agent. Collect process memory dump before termination for forensics.",
        "automated": True,
        "estimated_time": "< 1 minute",
    },
    "quarantine_file": {
        "category": "containment",
        "icon": "archive",
        "risk": "low",
        "description_template": "Quarantine malicious file on {hostname}",
        "details_template": "Move identified malicious file to quarantine on {hostname}. Compute and record file hash for IOC tracking.",
        "automated": True,
        "estimated_time": "< 1 minute",
    },
    "revoke_cloud_keys": {
        "category": "containment",
        "icon": "cloud-off",
        "risk": "high",
        "description_template": "Revoke AWS access keys for {user}",
        "details_template": "Deactivate all IAM access keys for {user} and remove inline/attached admin policies. Audit CloudTrail for actions performed with compromised credentials.",
        "automated": True,
        "estimated_time": "1-2 minutes",
    },
    "terminate_instance": {
        "category": "containment",
        "icon": "server-off",
        "risk": "medium",
        "description_template": "Terminate compromised EC2 instance {hostname}",
        "details_template": "Stop and snapshot EC2 instance {hostname} for forensic analysis, then terminate. Remove associated security group rules allowing inbound access.",
        "automated": True,
        "estimated_time": "2-5 minutes",
    },
    "remove_mail_rule": {
        "category": "remediation",
        "icon": "mail-x",
        "risk": "low",
        "description_template": "Remove malicious mail forwarding rule for {user}",
        "details_template": "Delete the inbox forwarding rule sending emails to external address. Audit sent items and forwarded emails for data exposure assessment.",
        "automated": True,
        "estimated_time": "< 1 minute",
    },
    "reset_krbtgt": {
        "category": "remediation",
        "icon": "refresh-cw",
        "risk": "critical",
        "description_template": "Reset KRBTGT account password (twice)",
        "details_template": "Perform double KRBTGT password reset to invalidate any forged golden tickets. This requires careful scheduling as it temporarily disrupts Kerberos authentication domain-wide.",
        "automated": False,
        "estimated_time": "30-60 minutes",
    },
    "restore_s3_policy": {
        "category": "remediation",
        "icon": "lock",
        "risk": "low",
        "description_template": "Restore private access policy on S3 bucket",
        "details_template": "Revert the S3 bucket policy to deny public access. Enable S3 Block Public Access at account level. Audit access logs for unauthorized downloads.",
        "automated": True,
        "estimated_time": "< 1 minute",
    },
    "network_scan": {
        "category": "investigation",
        "icon": "search",
        "risk": "low",
        "description_template": "Scan network for additional compromised hosts",
        "details_template": "Run network-wide IOC scan using identified indicators (IPs, hashes, domains). Check for signs of lateral movement to unidentified hosts.",
        "automated": True,
        "estimated_time": "15-30 minutes",
    },
    "forensic_image": {
        "category": "investigation",
        "icon": "hard-drive",
        "risk": "low",
        "description_template": "Capture forensic image of {hostname}",
        "details_template": "Create full disk and memory forensic image of {hostname} for detailed post-incident analysis. Preserve chain of custody documentation.",
        "automated": False,
        "estimated_time": "1-4 hours",
    },
}


def generate_response_actions(incident, completeness_data):
    """
    Generate prioritized response actions for an incident based on
    the events observed and attack completeness.
    """
    actions = []
    action_id = 0
    events = incident.get("events", [])

    # Collect unique targets
    hostnames = set()
    users = set()
    external_ips = {}
    event_types = set()

    for event in events:
        if event.get("hostname"):
            hostnames.add(event["hostname"])
        if event.get("user"):
            users.add(event["user"])
        event_types.add(event.get("event_type", ""))

        for ip_field in ["src_ip"]:
            ip = event.get(ip_field)
            if ip and not ip.startswith("10.") and not ip.startswith("192.168."):
                intel = event.get(f"{ip_field}_intel", {})
                external_ips[ip] = intel

    # ── Priority 1: Immediate containment ─────────────────────────────────
    # Block malicious external IPs
    for ip, intel in external_ips.items():
        if intel.get("reputation") in ["malicious", "suspicious"]:
            action_id += 1
            actions.append(_create_action(
                action_id, "block_ip", incident["id"],
                priority=1,
                confidence=0.95 if intel.get("reputation") == "malicious" else 0.80,
                params={"ip": ip, "geo": intel.get("geo", "Unknown")},
                reasoning=f"IP {ip} has {intel.get('reputation')} reputation with tags: {', '.join(intel.get('tags', []))}",
            ))

    # Isolate compromised hosts
    critical_events = {"ransomware", "credential_dump", "c2_communication", "process_execution", "lateral_movement"}
    for hostname in hostnames:
        host_events = [e for e in events if e.get("hostname") == hostname]
        host_event_types = {e.get("event_type") for e in host_events}
        if host_event_types & critical_events:
            action_id += 1
            actions.append(_create_action(
                action_id, "isolate_host", incident["id"],
                priority=1,
                confidence=0.90,
                params={"hostname": hostname},
                reasoning=f"Host {hostname} shows signs of active compromise: {', '.join(host_event_types & critical_events)}",
            ))

    # ── Priority 2: Credential containment ────────────────────────────────
    compromised_cred_events = {"credential_dump", "mfa_bypass", "suspicious_login", "brute_force"}
    for user in users:
        user_events = [e for e in events if e.get("user") == user]
        user_event_types = {e.get("event_type") for e in user_events}
        if user_event_types & compromised_cred_events:
            action_id += 1
            actions.append(_create_action(
                action_id, "disable_account", incident["id"],
                priority=2,
                confidence=0.88,
                params={"user": user},
                reasoning=f"Account {user} is likely compromised based on: {', '.join(user_event_types & compromised_cred_events)}",
            ))
            action_id += 1
            actions.append(_create_action(
                action_id, "reset_credentials", incident["id"],
                priority=3,
                confidence=0.88,
                params={"user": user},
                reasoning=f"Credentials for {user} should be rotated after compromise indicators",
            ))

    # ── Priority 3: Specific remediation ──────────────────────────────────
    if "process_execution" in event_types or "malware_detected" in event_types:
        for hostname in hostnames:
            action_id += 1
            actions.append(_create_action(
                action_id, "kill_process", incident["id"],
                priority=2,
                confidence=0.85,
                params={"hostname": hostname},
                reasoning=f"Malicious process execution detected on {hostname}",
            ))

    if "file_creation" in event_types or "malware_detected" in event_types:
        for hostname in hostnames:
            action_id += 1
            actions.append(_create_action(
                action_id, "quarantine_file", incident["id"],
                priority=2,
                confidence=0.90,
                params={"hostname": hostname},
                reasoning=f"Malicious file detected on {hostname}",
            ))

    if "email_forwarding" in event_types:
        for user in users:
            action_id += 1
            actions.append(_create_action(
                action_id, "remove_mail_rule", incident["id"],
                priority=2,
                confidence=0.95,
                params={"user": user},
                reasoning=f"Malicious mail forwarding rule detected for {user}",
            ))

    if "iam_change" in event_types or "crypto_mining" in event_types:
        for user in users:
            action_id += 1
            actions.append(_create_action(
                action_id, "revoke_cloud_keys", incident["id"],
                priority=1,
                confidence=0.92,
                params={"user": user},
                reasoning=f"Compromised cloud credentials used for unauthorized resource access",
            ))

    if "crypto_mining" in event_types:
        for hostname in hostnames:
            if hostname.startswith("i-"):
                action_id += 1
                actions.append(_create_action(
                    action_id, "terminate_instance", incident["id"],
                    priority=2,
                    confidence=0.88,
                    params={"hostname": hostname},
                    reasoning=f"EC2 instance {hostname} is running unauthorized cryptomining workloads",
                ))

    if "persistence" in event_types:
        for event in events:
            if event.get("event_type") == "persistence" and "golden ticket" in event.get("description", "").lower():
                action_id += 1
                actions.append(_create_action(
                    action_id, "reset_krbtgt", incident["id"],
                    priority=2,
                    confidence=0.85,
                    params={},
                    reasoning="Golden ticket attack detected — KRBTGT password must be reset to invalidate forged tickets",
                ))
                break

    if "s3_public" in event_types:
        action_id += 1
        actions.append(_create_action(
            action_id, "restore_s3_policy", incident["id"],
            priority=1,
            confidence=0.95,
            params={},
            reasoning="S3 bucket containing sensitive data has been made publicly accessible",
        ))

    # ── Priority 4: Investigation ─────────────────────────────────────────
    if completeness_data.get("completeness_percent", 0) >= 30:
        action_id += 1
        actions.append(_create_action(
            action_id, "network_scan", incident["id"],
            priority=4,
            confidence=0.75,
            params={},
            reasoning=f"Attack has reached {completeness_data.get('completeness_percent', 0)}% kill-chain completeness — scan for undiscovered compromise",
        ))

    if any(e.get("severity") == "critical" for e in events):
        for hostname in list(hostnames)[:2]:
            action_id += 1
            actions.append(_create_action(
                action_id, "forensic_image", incident["id"],
                priority=5,
                confidence=0.70,
                params={"hostname": hostname},
                reasoning=f"Critical severity events on {hostname} — forensic evidence preservation recommended",
            ))

    # Sort by priority then confidence
    actions.sort(key=lambda a: (a["priority"], -a["confidence"]))

    return actions


def _create_action(action_id, template_key, incident_id, priority, confidence, params, reasoning):
    """Create a structured response action from a template."""
    template = ACTION_TEMPLATES[template_key]

    # Format strings with params
    description = template["description_template"].format(**params) if params else template["description_template"]
    details = template["details_template"].format(**params) if params else template["details_template"]

    # Calculate trust score (combines confidence with action risk)
    risk_penalties = {"low": 0, "medium": 0.05, "high": 0.10, "critical": 0.15}
    trust_score = round(confidence - risk_penalties.get(template["risk"], 0), 2)

    return {
        "id": f"ACT-{action_id:03d}",
        "incident_id": incident_id,
        "action_type": template_key,
        "category": template["category"],
        "icon": template["icon"],
        "priority": priority,
        "description": description,
        "details": details,
        "risk_level": template["risk"],
        "confidence": confidence,
        "trust_score": trust_score,
        "automated": template["automated"],
        "estimated_time": template["estimated_time"],
        "reasoning": reasoning,
        "status": "pending",
        "created_at": datetime.utcnow().isoformat() + "Z",
        "approved_by": None,
        "approved_at": None,
    }


def generate_all_responses(incidents, attack_analyses):
    """Generate response actions for all incidents."""
    all_actions = []
    analysis_map = {a["incident_id"]: a for a in attack_analyses}

    for incident in incidents:
        analysis = analysis_map.get(incident["id"], {})
        completeness = analysis.get("completeness", {})
        actions = generate_response_actions(incident, completeness)
        all_actions.extend(actions)

    return all_actions


def get_response_summary(actions):
    """Get a summary of all pending response actions."""
    by_category = {}
    by_priority = {}
    by_status = {}

    for action in actions:
        cat = action.get("category", "unknown")
        by_category[cat] = by_category.get(cat, 0) + 1

        pri = action.get("priority", 0)
        by_priority[pri] = by_priority.get(pri, 0) + 1

        status = action.get("status", "pending")
        by_status[status] = by_status.get(status, 0) + 1

    return {
        "total_actions": len(actions),
        "by_category": by_category,
        "by_priority": by_priority,
        "by_status": by_status,
        "avg_confidence": round(sum(a["confidence"] for a in actions) / max(len(actions), 1), 2),
        "avg_trust_score": round(sum(a["trust_score"] for a in actions) / max(len(actions), 1), 2),
    }
