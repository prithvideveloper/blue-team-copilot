"""
Signal Fusion Agent — Detection Module
Ingests raw security logs, deduplicates, enriches, correlates alerts by IP/user/time,
assigns severity scores, and groups correlated events into Incidents.
"""

import json
import os
from datetime import datetime, timedelta
from collections import defaultdict

# ─── Threat Intelligence (simulated) ──────────────────────────────────────────
THREAT_INTEL = {
    "185.220.101.34": {"reputation": "malicious", "tags": ["tor-exit", "scanner"], "geo": "Germany", "asn": "AS205100"},
    "91.234.99.42":   {"reputation": "malicious", "tags": ["c2-server", "exfiltration"], "geo": "Russia", "asn": "AS44477"},
    "198.51.100.77":  {"reputation": "suspicious", "tags": ["brute-force", "proxy"], "geo": "Nigeria", "asn": "AS37560"},
    "203.0.113.45":   {"reputation": "suspicious", "tags": ["compromised-infra"], "geo": "Singapore", "asn": "AS13335"},
    "45.77.123.88":   {"reputation": "malicious", "tags": ["emotet-c2", "botnet"], "geo": "Netherlands", "asn": "AS20473"},
    "103.235.46.22":  {"reputation": "suspicious", "tags": ["vpn-exit", "anomalous"], "geo": "India", "asn": "AS55836"},
}

SEVERITY_WEIGHTS = {"low": 1, "medium": 3, "high": 7, "critical": 10}

# ─── MITRE ATT&CK Mapping ────────────────────────────────────────────────────
EVENT_TO_MITRE = {
    "connection_attempt":   {"tactic": "Reconnaissance",       "technique": "T1595 — Active Scanning"},
    "sql_injection_attempt":{"tactic": "Initial Access",       "technique": "T1190 — Exploit Public-Facing Application"},
    "rce_attempt":          {"tactic": "Initial Access",       "technique": "T1190 — Exploit Public-Facing Application"},
    "process_execution":    {"tactic": "Execution",            "technique": "T1059 — Command and Scripting Interpreter"},
    "file_creation":        {"tactic": "Persistence",          "technique": "T1505.003 — Web Shell"},
    "credential_dump":      {"tactic": "Credential Access",    "technique": "T1003 — OS Credential Dumping"},
    "suspicious_login":     {"tactic": "Lateral Movement",     "technique": "T1078 — Valid Accounts"},
    "lateral_movement":     {"tactic": "Lateral Movement",     "technique": "T1021 — Remote Services"},
    "data_staging":         {"tactic": "Collection",           "technique": "T1074 — Data Staged"},
    "data_exfiltration":    {"tactic": "Exfiltration",         "technique": "T1041 — Exfiltration Over C2 Channel"},
    "persistence":          {"tactic": "Persistence",          "technique": "T1053 — Scheduled Task/Job"},
    "brute_force":          {"tactic": "Credential Access",    "technique": "T1110 — Brute Force"},
    "mfa_bypass":           {"tactic": "Credential Access",    "technique": "T1621 — MFA Request Generation"},
    "email_forwarding":     {"tactic": "Collection",           "technique": "T1114.003 — Email Forwarding Rule"},
    "iam_change":           {"tactic": "Privilege Escalation", "technique": "T1098 — Account Manipulation"},
    "resource_creation":    {"tactic": "Execution",            "technique": "T1204 — User Execution"},
    "crypto_mining":        {"tactic": "Impact",               "technique": "T1496 — Resource Hijacking"},
    "malware_detected":     {"tactic": "Execution",            "technique": "T1204.002 — Malicious File"},
    "c2_communication":     {"tactic": "Command and Control",  "technique": "T1071 — Application Layer Protocol"},
    "dns_tunneling":        {"tactic": "Command and Control",  "technique": "T1071.004 — DNS"},
    "impossible_travel":    {"tactic": "Initial Access",       "technique": "T1078 — Valid Accounts"},
    "s3_public":            {"tactic": "Exfiltration",         "technique": "T1537 — Transfer to Cloud Account"},
    "ransomware":           {"tactic": "Impact",               "technique": "T1486 — Data Encrypted for Impact"},
}


def load_logs(filepath=None):
    """Load raw logs from JSON file."""
    if filepath is None:
        filepath = os.path.join(os.path.dirname(__file__), "logs.json")
    with open(filepath, "r") as f:
        return json.load(f)


def enrich_event(event):
    """Enrich a single event with threat intel and MITRE mapping."""
    enriched = dict(event)

    # Threat intel enrichment
    for ip_field in ["src_ip", "dst_ip"]:
        ip = event.get(ip_field)
        if ip and ip in THREAT_INTEL:
            enriched[f"{ip_field}_intel"] = THREAT_INTEL[ip]

    # MITRE ATT&CK mapping
    etype = event.get("event_type", "")
    if etype in EVENT_TO_MITRE:
        enriched["mitre"] = EVENT_TO_MITRE[etype]

    # Severity score
    enriched["severity_score"] = SEVERITY_WEIGHTS.get(event.get("severity", "low"), 1)

    # Boost score if IP has malicious reputation
    for ip_field in ["src_ip", "dst_ip"]:
        ip = event.get(ip_field)
        if ip and ip in THREAT_INTEL:
            rep = THREAT_INTEL[ip]["reputation"]
            if rep == "malicious":
                enriched["severity_score"] = min(10, enriched["severity_score"] + 3)
            elif rep == "suspicious":
                enriched["severity_score"] = min(10, enriched["severity_score"] + 1)

    return enriched


def correlate_events(events, time_window_minutes=30):
    """
    Correlate enriched events into incidents by grouping events that share
    IP addresses, users, or hostnames within the correlation time window.
    Uses union-find for transitive correlation.
    """
    # Parse timestamps
    for evt in events:
        if isinstance(evt.get("timestamp"), str):
            evt["_ts"] = datetime.fromisoformat(evt["timestamp"].replace("Z", "+00:00"))

    # Build an adjacency of related events
    n = len(events)
    parent = list(range(n))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    # Correlate by shared attributes within time window
    for i in range(n):
        for j in range(i + 1, n):
            ei, ej = events[i], events[j]
            time_diff = abs((ei["_ts"] - ej["_ts"]).total_seconds())
            if time_diff > time_window_minutes * 60:
                continue
            # Check shared IPs
            ips_i = {ei.get("src_ip"), ei.get("dst_ip")} - {None}
            ips_j = {ej.get("src_ip"), ej.get("dst_ip")} - {None}
            shared_ips = ips_i & ips_j

            # Check shared user/hostname
            shared_user = (ei.get("user") and ei.get("user") == ej.get("user"))
            shared_host = (ei.get("hostname") and ei.get("hostname") == ej.get("hostname"))

            # Check if destination of one is source of another (attack chain)
            chain = (ei.get("dst_ip") and ei.get("dst_ip") == ej.get("src_ip")) or \
                    (ej.get("dst_ip") and ej.get("dst_ip") == ei.get("src_ip"))

            if shared_ips or shared_user or shared_host or chain:
                union(i, j)

    # Group into incidents
    groups = defaultdict(list)
    for i in range(n):
        groups[find(i)].append(events[i])

    return groups


def build_incidents(event_groups):
    """Convert correlated groups into structured Incident objects."""
    incidents = []
    for idx, (_, group) in enumerate(sorted(event_groups.items()), 1):
        # Sort by timestamp
        group.sort(key=lambda e: e["_ts"])

        # Compute aggregate severity
        max_severity = max(e.get("severity_score", 1) for e in group)
        avg_severity = sum(e.get("severity_score", 1) for e in group) / len(group)
        combined_score = round(min(10, (max_severity * 0.6 + avg_severity * 0.4)), 1)

        # Determine affected assets
        hosts = set()
        users = set()
        ips = set()
        sources = set()
        tactics = set()
        for e in group:
            if e.get("hostname"): hosts.add(e["hostname"])
            if e.get("user"): users.add(e["user"])
            for f in ["src_ip", "dst_ip"]:
                if e.get(f): ips.add(e[f])
            sources.add(e.get("source", "unknown"))
            if e.get("mitre"):
                tactics.add(e["mitre"]["tactic"])

        # Classify incident
        if combined_score >= 8:
            threat_level = "critical"
        elif combined_score >= 6:
            threat_level = "high"
        elif combined_score >= 4:
            threat_level = "medium"
        else:
            threat_level = "low"

        # Generate incident title
        title = _generate_title(group, tactics)

        incident = {
            "id": f"INC-{idx:03d}",
            "title": title,
            "threat_level": threat_level,
            "combined_score": combined_score,
            "event_count": len(group),
            "first_seen": group[0]["timestamp"],
            "last_seen": group[-1]["timestamp"],
            "affected_hosts": sorted(hosts),
            "affected_users": sorted(users),
            "involved_ips": sorted(ips),
            "data_sources": sorted(sources),
            "tactics": sorted(tactics),
            "events": [{k: v for k, v in e.items() if k != "_ts"} for e in group],
        }
        incidents.append(incident)

    # Sort by severity descending
    incidents.sort(key=lambda inc: inc["combined_score"], reverse=True)
    # Re-number after sort
    for i, inc in enumerate(incidents, 1):
        inc["id"] = f"INC-{i:03d}"

    return incidents


def _generate_title(events, tactics):
    """Generate a human-readable incident title."""
    event_types = [e.get("event_type") for e in events]

    if "ransomware" in event_types:
        return "Ransomware Attack with Lateral Spread"
    if "data_exfiltration" in event_types:
        return "Multi-Stage Intrusion with Data Exfiltration"
    if "mfa_bypass" in event_types:
        return "Account Compromise via MFA Fatigue Attack"
    if "crypto_mining" in event_types:
        return "Cloud Infrastructure Abuse — Cryptomining"
    if "c2_communication" in event_types:
        return "Malware Infection with C2 Communication"
    if "impossible_travel" in event_types:
        return "Suspicious Login — Impossible Travel Detected"
    if "s3_public" in event_types:
        return "Cloud Misconfiguration — Public S3 Bucket"
    if any("lateral" in t for t in event_types):
        return "Lateral Movement Detected"
    if len(tactics) >= 3:
        return f"Multi-Tactic Attack ({', '.join(sorted(tactics)[:3])})"
    return f"Security Incident ({len(events)} events)"


def run_detection_pipeline(filepath=None, events=None):
    """Run the full detection pipeline and return enriched incidents.
    
    Args:
        filepath: Path to a JSON log file (used if events is None)
        events: Pre-loaded list of event dicts (e.g., from real-time dataset)
    """
    if events is not None:
        raw_logs = events
    else:
        raw_logs = load_logs(filepath)
    enriched = [enrich_event(e) for e in raw_logs]
    groups = correlate_events(enriched)
    incidents = build_incidents(groups)
    return {
        "total_raw_events": len(raw_logs),
        "total_enriched_events": len(enriched),
        "total_incidents": len(incidents),
        "incidents": incidents,
    }
