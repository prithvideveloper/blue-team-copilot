"""
AI Engine — Central AI Service for Blue Team Co-Pilot
Integrates Groq API (Llama 3.1) for all AI-powered features:
  - Incident Analysis
  - Threat Hunting
  - Executive Reports
  - Dashboard Insights
  - Attack Progression Prediction
"""

import os
import json
import httpx  # type: ignore
from typing import Dict, List, Any, Optional
from datetime import datetime

# ─── Configuration ────────────────────────────────────────────────────────────
GROQ_API_KEY = os.getenv(
    "GROQ_API_KEY",
    "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"
)
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = "llama-3.1-8b-instant"


async def _call_groq(messages: List[Dict[str, str]], max_tokens: int = 1024) -> str:
    """Make an async call to the Groq API."""
    if not GROQ_API_KEY:
        return "⚠️ AI Engine unavailable — Groq API key not configured."

    try:
        async with httpx.AsyncClient(timeout=45.0) as client:
            resp = await client.post(
                GROQ_API_URL,
                headers={
                    "Authorization": f"Bearer {GROQ_API_KEY}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": GROQ_MODEL,
                    "messages": messages,
                    "max_tokens": max_tokens,
                    "temperature": 0.3,
                },
            )
            if resp.status_code == 200:
                data = resp.json()
                return data["choices"][0]["message"]["content"]
            else:
                return f"⚠️ Groq API error {resp.status_code}: {resp.text[:200]}"
    except Exception as e:
        return f"⚠️ AI Engine error: {str(e)}"


# ─── AI Incident Analysis ────────────────────────────────────────────────────
async def ai_analyze_incident(incident: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate a comprehensive AI analysis of an incident.
    Returns executive summary, risk assessment, predicted next moves, and priorities.
    """
    # Build a compact incident summary for the prompt
    events_summary = []
    for evt in incident.get("events", [])[:15]:  # Limit to 15 events
        events_summary.append(
            f"- [{evt.get('severity', 'unknown').upper()}] {evt.get('timestamp', '')}: "
            f"{evt.get('event_type', '')} — {evt.get('description', '')}"
        )

    prompt = f"""You are a senior SOC analyst AI. Analyze this security incident and provide a detailed assessment.

**Incident: {incident.get('title', 'Unknown')}**
- ID: {incident.get('id', '?')}
- Threat Level: {incident.get('threat_level', '?')}
- Score: {incident.get('combined_score', '?')}/10
- Affected Hosts: {', '.join(incident.get('affected_hosts', []))}
- Affected Users: {', '.join(incident.get('affected_users', []))}
- MITRE Tactics: {', '.join(incident.get('tactics', []))}
- Time Window: {incident.get('first_seen', '')} to {incident.get('last_seen', '')}

**Events ({incident.get('event_count', 0)} total):**
{chr(10).join(events_summary)}

Provide your analysis in this EXACT JSON format (no markdown, just raw JSON):
{{
  "executive_summary": "2-3 sentence executive summary of the attack",
  "attack_narrative": "Detailed paragraph describing the attack chain step by step",
  "risk_assessment": {{
    "level": "CRITICAL/HIGH/MEDIUM/LOW",
    "business_impact": "Description of potential business impact",
    "data_at_risk": "What data may be compromised"
  }},
  "predicted_next_moves": [
    "Prediction 1: What the attacker might do next",
    "Prediction 2: Another possible next move",
    "Prediction 3: Another possible next move"
  ],
  "recommended_priorities": [
    "Priority 1: Most urgent action",
    "Priority 2: Second priority",
    "Priority 3: Third priority"
  ],
  "indicators_of_compromise": [
    "IOC 1",
    "IOC 2"
  ],
  "confidence_score": 0.85
}}"""

    messages = [
        {"role": "system", "content": "You are a cybersecurity expert AI. Always respond with valid JSON only, no markdown formatting."},
        {"role": "user", "content": prompt},
    ]

    raw = await _call_groq(messages, max_tokens=1200)

    try:
        # Try to parse as JSON
        clean = raw.strip()
        if clean.startswith("```"):
            clean = clean.split("\n", 1)[1] if "\n" in clean else clean[3:]
            clean = clean.rsplit("```", 1)[0]
        result = json.loads(clean)
        result["generated_at"] = datetime.utcnow().isoformat() + "Z"
        result["model"] = GROQ_MODEL
        return result
    except json.JSONDecodeError:
        return {
            "executive_summary": raw[:500],
            "attack_narrative": raw,
            "risk_assessment": {"level": incident.get("threat_level", "UNKNOWN").upper(), "business_impact": "AI could not parse structured response", "data_at_risk": "Unknown"},
            "predicted_next_moves": ["Review AI response manually"],
            "recommended_priorities": ["Escalate to senior analyst"],
            "indicators_of_compromise": [],
            "confidence_score": 0.5,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "model": GROQ_MODEL,
        }


# ─── AI Threat Hunting ───────────────────────────────────────────────────────
async def ai_threat_hunt(query: str, incidents: List[Dict[str, Any]], alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    AI-powered threat hunting across all incident and alert data.
    Accepts natural language queries and returns AI-curated findings.
    """
    # Build a context summary of all incidents
    incident_context = []
    for inc in incidents[:10]:
        incident_context.append(
            f"- {inc.get('id', '?')}: {inc.get('title', '?')} | "
            f"Severity: {inc.get('threat_level', '?')} | "
            f"Score: {inc.get('combined_score', '?')} | "
            f"Hosts: {', '.join(inc.get('affected_hosts', []))} | "
            f"Users: {', '.join(inc.get('affected_users', []))} | "
            f"Tactics: {', '.join(inc.get('tactics', []))}"
        )

    # Build alert context
    alert_sample = []
    for alert in alerts[:20]:
        alert_sample.append(
            f"- [{alert.get('severity', '?').upper()}] {alert.get('event_type', '?')}: "
            f"{alert.get('description', '?')[:100]} | "
            f"Source: {alert.get('src_ip', 'N/A')} → {alert.get('dst_ip', 'N/A')}"
        )

    prompt = f"""You are an elite threat hunter AI for a SOC. A security analyst has submitted this threat hunting query:

**Query:** "{query}"

**Current Incident Data ({len(incidents)} incidents):**
{chr(10).join(incident_context)}

**Recent Alerts (sample of {len(alert_sample)}):**
{chr(10).join(alert_sample)}

Analyze the data against the query and respond in this EXACT JSON format:
{{
  "findings": [
    {{
      "title": "Finding title",
      "description": "Detailed description of the finding",
      "severity": "critical/high/medium/low",
      "related_incidents": ["INC-001"],
      "evidence": ["Specific evidence point 1", "Evidence point 2"],
      "recommendation": "What to do about this finding"
    }}
  ],
  "hunt_summary": "Overall summary of the threat hunt",
  "threat_score": 75,
  "techniques_found": ["T1595", "T1190"],
  "recommendations": ["Recommendation 1", "Recommendation 2"]
}}"""

    messages = [
        {"role": "system", "content": "You are a cybersecurity threat hunter. Always respond with valid JSON only."},
        {"role": "user", "content": prompt},
    ]

    raw = await _call_groq(messages, max_tokens=1500)

    try:
        clean = raw.strip()
        if clean.startswith("```"):
            clean = clean.split("\n", 1)[1] if "\n" in clean else clean[3:]
            clean = clean.rsplit("```", 1)[0]
        result = json.loads(clean)
        result["query"] = query
        result["generated_at"] = datetime.utcnow().isoformat() + "Z"
        result["data_sources_searched"] = {
            "incidents": len(incidents),
            "alerts": len(alerts),
        }
        return result
    except json.JSONDecodeError:
        return {
            "findings": [{"title": "AI Analysis", "description": raw, "severity": "medium", "related_incidents": [], "evidence": [], "recommendation": "Review manually"}],
            "hunt_summary": raw[:300],
            "threat_score": 50,
            "techniques_found": [],
            "recommendations": ["Review AI response manually"],
            "query": query,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "data_sources_searched": {"incidents": len(incidents), "alerts": len(alerts)},
        }


# ─── AI Executive Report ─────────────────────────────────────────────────────
async def ai_generate_report(incidents: List[Dict[str, Any]], actions: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generate an AI-written executive security report.
    """
    # Build incident summary
    incident_info = []
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for inc in incidents:
        level = inc.get("threat_level", "low")
        severity_counts[level] = severity_counts.get(level, 0) + 1
        incident_info.append(
            f"- {inc.get('id', '?')}: {inc.get('title', '?')} [{level.upper()}] "
            f"(Score: {inc.get('combined_score', '?')}/10, {inc.get('event_count', 0)} events)"
        )

    # Action summary
    action_counts = {"pending": 0, "approved": 0, "rejected": 0}
    for act in actions:
        status = act.get("status", "pending")
        action_counts[status] = action_counts.get(status, 0) + 1

    prompt = f"""You are a senior CISO writing an executive security report. Generate a comprehensive, professional report in Markdown format.

**Security Data Summary:**
- Total Incidents: {len(incidents)}
- Severity Breakdown: {json.dumps(severity_counts)}
- Total Response Actions: {len(actions)} ({action_counts['pending']} pending, {action_counts['approved']} approved)
- Report Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}

**Incidents:**
{chr(10).join(incident_info)}

Write a professional executive security report with these sections:
1. **Executive Summary** — 2-3 paragraph overview for C-level executives
2. **Threat Landscape** — Current threat environment based on the incidents
3. **Critical Incidents** — Detail the most severe incidents
4. **Attack Patterns** — MITRE ATT&CK patterns observed
5. **Response Status** — Status of containment/remediation actions
6. **Risk Assessment** — Overall organizational risk level
7. **Recommendations** — Top 5 strategic recommendations
8. **Metrics Dashboard** — Key security metrics in a table

Use professional language, include severity indicators, and make it suitable for board-level presentation."""

    messages = [
        {"role": "system", "content": "You are a CISO writing executive security reports. Use professional Markdown formatting."},
        {"role": "user", "content": prompt},
    ]

    report_content = await _call_groq(messages, max_tokens=2048)

    return {
        "title": f"Executive Security Report — {datetime.utcnow().strftime('%B %d, %Y')}",
        "content": report_content,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "model": GROQ_MODEL,
        "data_summary": {
            "total_incidents": len(incidents),
            "severity_counts": severity_counts,
            "total_actions": len(actions),
            "action_status": action_counts,
        },
    }


# ─── AI Dashboard Insights ───────────────────────────────────────────────────
async def ai_dashboard_insights(
    incidents: List[Dict[str, Any]],
    severity_counts: Dict[str, int],
    tactic_counts: Dict[str, int],
    total_events: int,
) -> Dict[str, Any]:
    """
    Generate AI-powered insights for the dashboard.
    """
    prompt = f"""You are a SOC AI assistant. Analyze the current security posture and provide insights.

**Current Security Posture:**
- Total Events Analyzed: {total_events}
- Active Incidents: {len(incidents)}
- Severity Breakdown: Critical={severity_counts.get('critical',0)}, High={severity_counts.get('high',0)}, Medium={severity_counts.get('medium',0)}, Low={severity_counts.get('low',0)}
- MITRE Tactics Observed: {', '.join(list(tactic_counts.keys())[:8])}

**Top Incidents:**
{chr(10).join(f'- {inc.get("title","?")} [{inc.get("threat_level","?").upper()}]' for inc in incidents[:5])}

Provide insights in this EXACT JSON format:
{{
  "threat_summary": "One paragraph overall threat assessment",
  "risk_level": "CRITICAL/HIGH/MEDIUM/LOW",
  "risk_score": 85,
  "key_insights": [
    "Insight 1 about the current security state",
    "Insight 2 about patterns detected",
    "Insight 3 about what to watch for"
  ],
  "predicted_threats": [
    "Prediction 1: What might happen next",
    "Prediction 2: Another potential risk"
  ],
  "quick_wins": [
    "Quick action 1 to improve security",
    "Quick action 2"
  ]
}}"""

    messages = [
        {"role": "system", "content": "You are a SOC AI. Respond with valid JSON only."},
        {"role": "user", "content": prompt},
    ]

    raw = await _call_groq(messages, max_tokens=800)

    try:
        clean = raw.strip()
        if clean.startswith("```"):
            clean = clean.split("\n", 1)[1] if "\n" in clean else clean[3:]
            clean = clean.rsplit("```", 1)[0]
        result = json.loads(clean)
        result["generated_at"] = datetime.utcnow().isoformat() + "Z"
        return result
    except json.JSONDecodeError:
        return {
            "threat_summary": raw[:400],
            "risk_level": "HIGH" if severity_counts.get("critical", 0) > 0 else "MEDIUM",
            "risk_score": 75,
            "key_insights": ["AI analysis available — see response"],
            "predicted_threats": ["Review full AI output for predictions"],
            "quick_wins": ["Check AI output for recommendations"],
            "generated_at": datetime.utcnow().isoformat() + "Z",
        }


# ─── AI Attack Progression Prediction ────────────────────────────────────────
async def ai_predict_attack_progression(incident: Dict[str, Any]) -> Dict[str, Any]:
    """
    Predict what MITRE ATT&CK phases the attacker will likely attempt next.
    """
    observed_tactics = incident.get("tactics", [])

    prompt = f"""You are a threat intelligence AI. Given the following observed MITRE ATT&CK tactics in an active incident, predict what the attacker will likely do next.

**Incident:** {incident.get('title', 'Unknown')}
**Observed Tactics:** {', '.join(observed_tactics)}
**Threat Level:** {incident.get('threat_level', 'unknown')}
**Affected Hosts:** {', '.join(incident.get('affected_hosts', []))}

Respond in this EXACT JSON format:
{{
  "current_phase": "The current phase of the attack",
  "predicted_next_phases": [
    {{
      "phase": "MITRE ATT&CK Tactic name",
      "probability": 0.85,
      "description": "Why the attacker might attempt this",
      "indicators_to_watch": ["What to look for"]
    }}
  ],
  "time_estimate": "Estimated time before next phase",
  "overall_trajectory": "Description of where this attack is heading"
}}"""

    messages = [
        {"role": "system", "content": "You are a threat intelligence expert. Respond with valid JSON only."},
        {"role": "user", "content": prompt},
    ]

    raw = await _call_groq(messages, max_tokens=800)

    try:
        clean = raw.strip()
        if clean.startswith("```"):
            clean = clean.split("\n", 1)[1] if "\n" in clean else clean[3:]
            clean = clean.rsplit("```", 1)[0]
        result = json.loads(clean)
        result["generated_at"] = datetime.utcnow().isoformat() + "Z"
        return result
    except json.JSONDecodeError:
        return {
            "current_phase": "Analysis",
            "predicted_next_phases": [{"phase": "See AI response", "probability": 0.5, "description": raw[:200], "indicators_to_watch": []}],
            "time_estimate": "Unknown",
            "overall_trajectory": raw[:300],
            "generated_at": datetime.utcnow().isoformat() + "Z",
        }
