"""
Attack-Path Simulation Agent
Takes correlated incidents, maps events to MITRE ATT&CK kill-chain,
reconstructs the probable attack graph as directed nodes/edges,
and scores attack completeness.
"""

# ─── Kill Chain Order ─────────────────────────────────────────────────────────
KILL_CHAIN_ORDER = [
    "Reconnaissance",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

TACTIC_COLORS = {
    "Reconnaissance":      "#64748b",
    "Initial Access":      "#f59e0b",
    "Execution":           "#ef4444",
    "Persistence":         "#8b5cf6",
    "Privilege Escalation":"#ec4899",
    "Defense Evasion":     "#6366f1",
    "Credential Access":   "#f97316",
    "Discovery":           "#06b6d4",
    "Lateral Movement":    "#10b981",
    "Collection":          "#eab308",
    "Command and Control": "#e11d48",
    "Exfiltration":        "#dc2626",
    "Impact":              "#991b1b",
}


def build_attack_graph(incident):
    """
    Build a directed attack graph from an incident's events.
    Returns nodes (hosts/actions) and edges (attack flow).
    """
    nodes = []
    edges = []
    node_ids = set()
    event_nodes = []

    events = incident.get("events", [])

    for i, event in enumerate(events):
        # Create event node
        mitre = event.get("mitre", {})
        tactic = mitre.get("tactic", "Unknown")
        technique = mitre.get("technique", "Unknown")

        node_id = f"evt-{event.get('id', i)}"
        node = {
            "id": node_id,
            "type": "event",
            "label": event.get("event_type", "unknown").replace("_", " ").title(),
            "description": event.get("description", ""),
            "tactic": tactic,
            "technique": technique,
            "severity": event.get("severity", "low"),
            "severity_score": event.get("severity_score", 1),
            "timestamp": event.get("timestamp", ""),
            "source": event.get("source", ""),
            "hostname": event.get("hostname", ""),
            "color": TACTIC_COLORS.get(tactic, "#64748b"),
            "kill_chain_phase": KILL_CHAIN_ORDER.index(tactic) if tactic in KILL_CHAIN_ORDER else -1,
        }

        # Add host nodes
        hostname = event.get("hostname")
        if hostname and hostname not in node_ids:
            host_node = {
                "id": f"host-{hostname}",
                "type": "host",
                "label": hostname,
                "description": f"Host: {hostname}",
                "tactic": None,
                "technique": None,
                "severity": None,
                "severity_score": 0,
                "timestamp": None,
                "source": None,
                "hostname": hostname,
                "color": "#3b82f6",
                "kill_chain_phase": -1,
            }
            nodes.append(host_node)
            node_ids.add(hostname)

        # Add IP nodes for external IPs
        for ip_field in ["src_ip", "dst_ip"]:
            ip = event.get(ip_field)
            if ip and not ip.startswith("10.") and not ip.startswith("192.168.") and ip not in node_ids:
                intel = event.get(f"{ip_field}_intel", {})
                ip_node = {
                    "id": f"ip-{ip}",
                    "type": "external_ip",
                    "label": ip,
                    "description": f"External IP: {ip} ({intel.get('geo', 'Unknown')})",
                    "tactic": None,
                    "technique": None,
                    "severity": None,
                    "severity_score": 0,
                    "timestamp": None,
                    "source": None,
                    "hostname": None,
                    "color": "#ef4444" if intel.get("reputation") == "malicious" else "#f59e0b",
                    "kill_chain_phase": -1,
                    "intel": intel,
                }
                nodes.append(ip_node)
                node_ids.add(ip)

        nodes.append(node)
        node_ids.add(node_id)
        event_nodes.append((node_id, event))

    # Build edges
    for i in range(len(event_nodes)):
        nid, evt = event_nodes[i]

        # Connect external IPs to events
        src_ip = evt.get("src_ip")
        if src_ip and not src_ip.startswith("10.") and not src_ip.startswith("192.168."):
            edges.append({
                "source": f"ip-{src_ip}",
                "target": nid,
                "label": "originates from",
                "type": "attack_origin",
            })

        # Connect events to hosts
        hostname = evt.get("hostname")
        if hostname:
            edges.append({
                "source": nid,
                "target": f"host-{hostname}",
                "label": "targets",
                "type": "targets_host",
            })

        # Connect sequential events (kill chain flow)
        if i > 0:
            prev_nid, prev_evt = event_nodes[i - 1]
            # Connect if same host, same IP, or attack chain
            shared = False
            if evt.get("hostname") and evt.get("hostname") == prev_evt.get("hostname"):
                shared = True
            if evt.get("src_ip") and (evt.get("src_ip") == prev_evt.get("dst_ip")):
                shared = True
            if evt.get("user") and evt.get("user") == prev_evt.get("user"):
                shared = True

            if shared:
                edges.append({
                    "source": prev_nid,
                    "target": nid,
                    "label": "leads to",
                    "type": "kill_chain",
                })

    return {"nodes": nodes, "edges": edges}


def analyze_attack_completeness(incident):
    """
    Analyze how many kill-chain phases have been observed.
    Returns completeness score and phase details.
    """
    observed_tactics = set()
    phase_details = []

    for event in incident.get("events", []):
        mitre = event.get("mitre", {})
        tactic = mitre.get("tactic")
        if tactic:
            observed_tactics.add(tactic)

    for phase in KILL_CHAIN_ORDER:
        phase_details.append({
            "phase": phase,
            "observed": phase in observed_tactics,
            "color": TACTIC_COLORS.get(phase, "#64748b"),
        })

    completeness = round(len(observed_tactics) / len(KILL_CHAIN_ORDER) * 100, 1)

    return {
        "completeness_percent": completeness,
        "observed_phases": len(observed_tactics),
        "total_phases": len(KILL_CHAIN_ORDER),
        "phases": phase_details,
        "risk_assessment": _assess_risk(completeness, observed_tactics),
    }


def _assess_risk(completeness, tactics):
    """Generate risk assessment based on observed tactics."""
    if "Impact" in tactics:
        return {
            "level": "CRITICAL",
            "summary": "Attack has reached Impact phase — active damage occurring",
            "urgency": "IMMEDIATE",
        }
    if "Exfiltration" in tactics:
        return {
            "level": "CRITICAL",
            "summary": "Data exfiltration detected — sensitive data may be compromised",
            "urgency": "IMMEDIATE",
        }
    if "Lateral Movement" in tactics:
        return {
            "level": "HIGH",
            "summary": "Attacker has moved laterally — multiple systems compromised",
            "urgency": "HIGH",
        }
    if "Credential Access" in tactics:
        return {
            "level": "HIGH",
            "summary": "Credentials have been compromised — escalation likely",
            "urgency": "HIGH",
        }
    if completeness >= 40:
        return {
            "level": "MEDIUM",
            "summary": f"Multiple kill-chain phases observed ({completeness}%) — active attack in progress",
            "urgency": "MEDIUM",
        }
    return {
        "level": "LOW",
        "summary": "Early-stage activity detected — monitoring recommended",
        "urgency": "LOW",
    }


def build_full_attack_graph(incidents):
    """Build a combined attack graph from all incidents."""
    all_nodes = []
    all_edges = []
    seen_node_ids = set()

    for incident in incidents:
        graph = build_attack_graph(incident)
        for node in graph["nodes"]:
            if node["id"] not in seen_node_ids:
                node["incident_id"] = incident["id"]
                all_nodes.append(node)
                seen_node_ids.add(node["id"])
        for edge in graph["edges"]:
            edge["incident_id"] = incident["id"]
            all_edges.append(edge)

    return {"nodes": all_nodes, "edges": all_edges}


def run_attack_analysis(incidents):
    """Run attack path analysis on all incidents."""
    results = []
    for incident in incidents:
        graph = build_attack_graph(incident)
        completeness = analyze_attack_completeness(incident)
        results.append({
            "incident_id": incident["id"],
            "incident_title": incident["title"],
            "threat_level": incident["threat_level"],
            "graph": graph,
            "completeness": completeness,
        })
    return results
