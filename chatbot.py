"""
Blue Team Co-Pilot — Context-Aware AI Chatbot
Uses Groq API with real-time SOC context injected into every conversation.
The chatbot knows about actual incidents, alerts, and response actions.
"""

import os
import httpx  # type: ignore
import motor.motor_asyncio  # type: ignore
from fastapi import APIRouter, Request  # type: ignore

chatbot_router = APIRouter()

# ─── MongoDB for context ──────────────────────────────────────────────────────
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
_client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_URI)
_db = _client["blue_team_copilot"]


async def _build_soc_context() -> str:
    """Build a real-time SOC context string from the database."""
    try:
        # Count incidents by severity
        incidents = []
        async for doc in _db.incidents.find().sort("combined_score", -1).limit(10):
            incidents.append(doc)

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        all_tactics = set()
        for inc in incidents:
            severity_counts[inc.get("threat_level", "low")] += 1
            for t in inc.get("tactics", []):
                all_tactics.add(t)

        # Count pending actions
        pending = await _db.response_actions.count_documents({"status": "pending"})
        total_actions = await _db.response_actions.count_documents({})

        # Build incident list
        incident_lines = []
        for inc in incidents[:5]:
            incident_lines.append(
                f"  - {inc.get('id', '?')}: {inc.get('title', 'Unknown')} "
                f"[{inc.get('threat_level', '?').upper()}] "
                f"(Score: {inc.get('combined_score', '?')}/10, "
                f"{inc.get('event_count', 0)} events)"
            )

        context = f"""
CURRENT SOC STATUS (Real-Time Data):
- Total Active Incidents: {len(incidents)}
- Severity: {severity_counts['critical']} Critical, {severity_counts['high']} High, {severity_counts['medium']} Medium, {severity_counts['low']} Low
- Pending Response Actions: {pending}/{total_actions}
- MITRE ATT&CK Tactics Observed: {', '.join(sorted(all_tactics))}

TOP INCIDENTS:
{chr(10).join(incident_lines)}

You have access to this real-time data. When the analyst asks about incidents, actions, threats, or the current security posture, reference this data specifically. Use incident IDs (like INC-001) when referring to specific incidents."""

        return context
    except Exception:
        return "\n(SOC context unavailable — database may not be ready)"


@chatbot_router.post("/api/chat")
async def chat_endpoint(request: Request):
    """Context-aware chat endpoint powered by Groq AI."""
    data = await request.json()
    messages = data.get("messages", [])

    # Build the system prompt with real-time SOC context
    soc_context = await _build_soc_context()

    system_prompt = f"""You are the Blue Team Co-Pilot AI, an expert cybersecurity SOC assistant. You have real-time access to the security operations data below.

{soc_context}

YOUR CAPABILITIES:
- Explain security incidents and attack patterns using the real data above
- Interpret MITRE ATT&CK tactics and techniques
- Recommend containment and remediation actions
- Analyze indicators of compromise (IOCs)
- Provide guidance on threat hunting and forensics
- Answer questions about the current security posture with specific data

RULES:
- Be concise but thorough (2-4 sentences for simple questions, more for complex analysis)
- Always reference real incident IDs and data when relevant
- Provide actionable recommendations
- If asked about specific incidents, use the data above
- Format responses with bold text and bullet points for clarity"""

    # Replace or inject the system prompt
    filtered = [m for m in messages if m.get("role") != "system"]
    filtered.insert(0, {"role": "system", "content": system_prompt})

    api_key = os.getenv(
        "GROQ_API_KEY",
        "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"
    )

    if not api_key:
        return {"reply": "⚠️ API key is missing."}

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": "llama-3.1-8b-instant",
                    "messages": filtered,
                    "max_tokens": 800,
                    "temperature": 0.4,
                },
                timeout=30.0
            )

            if resp.status_code == 200:
                result = resp.json()
                reply = result["choices"][0]["message"]["content"]
                return {"reply": reply}
            else:
                return {"reply": f"⚠️ Groq API returned an error: {resp.status_code} - {resp.text}"}
    except Exception as e:
        return {"reply": f"⚠️ Error connecting to Groq API: {str(e)}"}
