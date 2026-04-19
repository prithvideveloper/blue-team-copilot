"""
Blue Team Co-Pilot — FastAPI Server
REST API + WebSocket for the live incident UI (MongoDB Backend).
Now with AI-powered analysis, real-time dataset, and threat hunting.
"""

import os
import asyncio
from datetime import datetime
from typing import Dict, List, Any, Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException  # type: ignore
from fastapi.middleware.cors import CORSMiddleware  # type: ignore
from pydantic import BaseModel  # type: ignore
import motor.motor_asyncio  # type: ignore

from detection import run_detection_pipeline  # type: ignore
from attack_path import run_attack_analysis, build_full_attack_graph  # type: ignore
from response import generate_all_responses, get_response_summary  # type: ignore
from chatbot import chatbot_router  # type: ignore
from auth import auth_router, seed_admin  # type: ignore
from threats import threats_router  # type: ignore
from ai_engine import (  # type: ignore
    ai_analyze_incident,
    ai_threat_hunt,
    ai_generate_report,
    ai_dashboard_insights,
    ai_predict_attack_progression,
)
from dataset_loader import fetch_real_dataset, get_dataset_info  # type: ignore

# ─── Initialize App ──────────────────────────────────────────────────────────
app = FastAPI(
    title="Blue Team Co-Pilot",
    description="AI-based multi-agent SOC assistant with real-time SIEM data, threat detection, attack-path analysis, AI threat hunting, and response orchestration",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(chatbot_router)
app.include_router(auth_router)
app.include_router(threats_router)

# ─── MongoDB Connection ──────────────────────────────────────────────────────
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_URI)
db = client["blue_team_copilot"]

def serialize_doc(doc):
    doc["_id"] = str(doc["_id"])
    return doc

# ─── Seeding Pipeline Data to MongoDB ────────────────────────────────────────
async def seed_core_data():
    """Run the pipeline and seed the database if it is empty."""
    count = await db.incidents.count_documents({})
    if count > 0:
        return  # Already seeded

    # Try to fetch real dataset first
    print("🌐 Attempting to fetch real SIEM dataset from Hugging Face...")
    try:
        real_events = await fetch_real_dataset(sample_size=200)
        if real_events and len(real_events) >= 20:
            print(f"✅ Loaded {len(real_events)} real events, running detection pipeline...")
            pipeline_data = run_detection_pipeline(events=real_events)
            dataset_source = "huggingface_realtime"
        else:
            raise ValueError("Not enough events from real dataset")
    except Exception as e:
        print(f"⚠️ Real dataset unavailable ({e}), using local logs.json...")
        pipeline_data = run_detection_pipeline()
        dataset_source = "local_logs"

    incidents = pipeline_data.get("incidents", [])
    attack_analyses = run_attack_analysis(incidents)
    full_graph = build_full_attack_graph(incidents)
    response_actions = generate_all_responses(incidents, attack_analyses)

    if incidents:
        await db.incidents.insert_many(incidents)
    if attack_analyses:
        await db.attack_analyses.insert_many(attack_analyses)
    if response_actions:
        await db.response_actions.insert_many(response_actions)
    if full_graph:
        await db.system_data.update_one({"_id": "attack_graph"}, {"$set": {"graph": full_graph}}, upsert=True)
    
    await db.system_data.update_one(
        {"_id": "pipeline_meta"}, 
        {"$set": {
            "total_raw_events": pipeline_data["total_raw_events"],
            "total_incidents": pipeline_data["total_incidents"],
            "dataset_source": dataset_source,
            "seeded_at": datetime.utcnow().isoformat() + "Z",
        }}, 
        upsert=True
    )

    # Store dataset info
    info = get_dataset_info()
    info["active_source"] = dataset_source
    await db.system_data.update_one(
        {"_id": "dataset_info"}, {"$set": info}, upsert=True
    )


@app.on_event("startup")
async def on_startup():
    await seed_admin()
    await seed_core_data()


# ─── WebSocket Connections ────────────────────────────────────────────────────
connected_clients: list[WebSocket] = []

# ─── REST Endpoints ──────────────────────────────────────────────────────────

@app.get("/api/dashboard")
async def get_dashboard():
    """Get dashboard summary data from MongoDB."""
    meta = await db.system_data.find_one({"_id": "pipeline_meta"})
    total_events = meta["total_raw_events"] if meta else 0
    total_incidents = meta["total_incidents"] if meta else 0

    incidents = []
    async for doc in db.incidents.find().sort("combined_score", -1):
        incidents.append(serialize_doc(doc))

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    source_counts = {}
    tactic_counts = {}

    for inc in incidents:
        severity_counts[inc["threat_level"]] = severity_counts.get(inc["threat_level"], 0) + 1
        for src in inc["data_sources"]:
            source_counts[src] = source_counts.get(src, 0) + 1
        for tactic in inc["tactics"]:
            tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1

    if severity_counts["critical"] > 0:
        overall_threat = "critical"
        threat_score = 95
    elif severity_counts["high"] > 0:
        overall_threat = "high"
        threat_score = 75
    elif severity_counts["medium"] > 0:
        overall_threat = "medium"
        threat_score = 50
    else:
        overall_threat = "low"
        threat_score = 20

    # Get response summary
    actions = []
    async for a in db.response_actions.find():
        actions.append(a)
    response_summary = get_response_summary(actions)

    # Dataset info
    ds_info = await db.system_data.find_one({"_id": "dataset_info"})
    dataset_name = ds_info.get("name", "Local Logs") if ds_info else "Local Logs"
    dataset_source = meta.get("dataset_source", "local") if meta else "local"

    return {
        "total_events": total_events,
        "total_incidents": total_incidents,
        "overall_threat_level": overall_threat,
        "threat_score": threat_score,
        "severity_breakdown": severity_counts,
        "source_breakdown": source_counts,
        "tactic_breakdown": tactic_counts,
        "pending_actions": response_summary["by_status"].get("pending", 0),
        "response_summary": response_summary,
        "dataset_info": {
            "name": dataset_name,
            "source": dataset_source,
        },
        "recent_incidents": [
            {
                "id": inc["id"],
                "title": inc["title"],
                "threat_level": inc["threat_level"],
                "event_count": inc["event_count"],
                "first_seen": inc["first_seen"],
                "last_seen": inc["last_seen"],
            }
            for inc in incidents[:5]
        ],
        "timeline": _build_timeline(incidents),
    }


@app.get("/api/alerts")
async def get_alerts(severity: Optional[str] = None, source: Optional[str] = None):
    """Get all enriched alerts with optional filtering."""
    incidents = []
    async for doc in db.incidents.find():
        incidents.append(doc)

    all_events = []
    for inc in incidents:
        for event in inc["events"]:
            event_copy = dict(event)
            event_copy["incident_id"] = inc["id"]
            event_copy["incident_title"] = inc["title"]
            all_events.append(event_copy)

    if severity:
        all_events = [e for e in all_events if e.get("severity") == severity]
    if source:
        all_events = [e for e in all_events if e.get("source") == source]

    all_events.sort(key=lambda e: (-e.get("severity_score", 0), e.get("timestamp", "")))

    return {
        "total": len(all_events),
        "alerts": all_events,
    }


@app.get("/api/incidents")
async def get_incidents():
    """Get all correlated incidents."""
    incidents = []
    async for doc in db.incidents.find().sort("combined_score", -1):
        incidents.append(serialize_doc(doc))

    return {
        "total": len(incidents),
        "incidents": [
            {
                "id": inc["id"],
                "title": inc["title"],
                "threat_level": inc["threat_level"],
                "combined_score": inc["combined_score"],
                "event_count": inc["event_count"],
                "first_seen": inc["first_seen"],
                "last_seen": inc["last_seen"],
                "affected_hosts": inc["affected_hosts"],
                "affected_users": inc["affected_users"],
                "data_sources": inc["data_sources"],
                "tactics": inc["tactics"],
            }
            for inc in incidents
        ],
    }


@app.get("/api/incidents/{incident_id}")
async def get_incident_detail(incident_id: str):
    """Get full incident detail including attack path and response actions."""
    incident = await db.incidents.find_one({"id": incident_id})
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    analysis = await db.attack_analyses.find_one({"incident_id": incident_id})
    if analysis:
        serialize_doc(analysis)

    inc_actions = []
    async for a in db.response_actions.find({"incident_id": incident_id}):
        inc_actions.append(serialize_doc(a))

    return {
        "incident": serialize_doc(incident),
        "attack_analysis": analysis,
        "response_actions": inc_actions,
    }


@app.get("/api/attack-graph")
async def get_attack_graph():
    """Get the full attack graph across all incidents."""
    doc = await db.system_data.find_one({"_id": "attack_graph"})
    if doc and "graph" in doc:
        return doc["graph"]
    return {}


@app.get("/api/actions")
async def get_all_actions():
    """Get all response actions across all incidents."""
    actions = []
    async for a in db.response_actions.find():
        actions.append(serialize_doc(a))
        
    return {
        "total": len(actions),
        "actions": actions,
        "summary": get_response_summary(actions),
    }


@app.post("/api/actions/{action_id}/approve")
async def approve_action(action_id: str):
    """Approve a pending response action."""
    action = await db.response_actions.find_one({"id": action_id})
    if not action:
        raise HTTPException(status_code=404, detail=f"Action {action_id} not found")
        
    if action["status"] != "pending":
        raise HTTPException(status_code=400, detail=f"Action {action_id} is already {action['status']}")
        
    update_data = {
        "status": "approved",
        "approved_by": "SOC Analyst",
        "approved_at": datetime.utcnow().isoformat() + "Z"
    }
    
    await db.response_actions.update_one({"id": action_id}, {"$set": update_data})
    action.update(update_data)
    action = serialize_doc(action)

    # Notify WebSocket clients
    await _broadcast({
        "type": "action_update",
        "action": action,
    })

    return {"message": f"Action {action_id} approved", "action": action}


@app.post("/api/actions/{action_id}/reject")
async def reject_action(action_id: str):
    """Reject a pending response action."""
    action = await db.response_actions.find_one({"id": action_id})
    if not action:
        raise HTTPException(status_code=404, detail=f"Action {action_id} not found")
        
    if action["status"] != "pending":
        raise HTTPException(status_code=400, detail=f"Action {action_id} is already {action['status']}")
        
    await db.response_actions.update_one({"id": action_id}, {"$set": {"status": "rejected"}})
    action["status"] = "rejected"
    action = serialize_doc(action)

    await _broadcast({
        "type": "action_update",
        "action": action,
    })

    return {"message": f"Action {action_id} rejected", "action": action}


# ═══════════════════════════════════════════════════════════════════════════════
# AI-POWERED ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/incidents/{incident_id}/ai-analysis")
async def get_ai_analysis(incident_id: str):
    """AI-generated analysis for a specific incident."""
    incident = await db.incidents.find_one({"id": incident_id})
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    # Remove MongoDB _id for serialization
    incident.pop("_id", None)
    analysis = await ai_analyze_incident(incident)
    return analysis


class ThreatHuntRequest(BaseModel):
    query: str

@app.post("/api/threat-hunt")
async def threat_hunt(req: ThreatHuntRequest):
    """AI-powered threat hunting across all data."""
    # Gather incident data
    incidents = []
    async for doc in db.incidents.find().sort("combined_score", -1):
        doc.pop("_id", None)
        incidents.append(doc)

    # Gather alert data
    alerts = []
    for inc in incidents:
        for event in inc.get("events", []):
            event_copy = dict(event)
            event_copy["incident_id"] = inc["id"]
            alerts.append(event_copy)

    result = await ai_threat_hunt(req.query, incidents, alerts)
    return result


@app.get("/api/reports/executive")
async def get_executive_report():
    """AI-generated executive security report."""
    incidents = []
    async for doc in db.incidents.find().sort("combined_score", -1):
        doc.pop("_id", None)
        incidents.append(doc)

    actions = []
    async for a in db.response_actions.find():
        a.pop("_id", None)
        actions.append(a)

    report = await ai_generate_report(incidents, actions)
    return report


@app.get("/api/dashboard/ai-insights")
async def get_ai_insights():
    """AI-generated dashboard insights and predictions."""
    incidents = []
    async for doc in db.incidents.find().sort("combined_score", -1):
        doc.pop("_id", None)
        incidents.append(doc)

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    tactic_counts = {}
    total_events = 0

    for inc in incidents:
        severity_counts[inc["threat_level"]] = severity_counts.get(inc["threat_level"], 0) + 1
        for tactic in inc["tactics"]:
            tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
        total_events += inc.get("event_count", 0)

    result = await ai_dashboard_insights(incidents, severity_counts, tactic_counts, total_events)
    return result


@app.get("/api/incidents/{incident_id}/ai-prediction")
async def get_ai_prediction(incident_id: str):
    """AI-predicted attack progression for an incident."""
    incident = await db.incidents.find_one({"id": incident_id})
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    incident.pop("_id", None)
    result = await ai_predict_attack_progression(incident)
    return result


@app.get("/api/dataset-info")
async def get_dataset_information():
    """Get information about the dataset being used."""
    ds_info = await db.system_data.find_one({"_id": "dataset_info"})
    if ds_info:
        ds_info.pop("_id", None)
        return ds_info

    return get_dataset_info()


@app.post("/api/dataset/refresh")
async def refresh_dataset():
    """Re-fetch the real-time dataset and re-seed the database."""
    # Drop existing data
    await db.incidents.drop()
    await db.attack_analyses.drop()
    await db.response_actions.drop()
    await db.system_data.delete_many({"_id": {"$in": ["attack_graph", "pipeline_meta", "dataset_info"]}})
    
    # Re-seed
    await seed_core_data()
    
    return {"message": "Dataset refreshed successfully", "timestamp": datetime.utcnow().isoformat() + "Z"}


# ─── WebSocket ────────────────────────────────────────────────────────────────

@app.websocket("/ws/live")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    connected_clients.append(ws)
    try:
        meta = await db.system_data.find_one({"_id": "pipeline_meta"})
        total_inc = meta["total_incidents"] if meta else 0
        total_evts = meta["total_raw_events"] if meta else 0
        
        await ws.send_json({
            "type": "connected",
            "message": "Connected to Blue Team Co-Pilot live feed",
            "incident_count": total_inc,
            "event_count": total_evts,
        })

        # Simulate live alert feed from DB
        all_events = []
        async for inc in db.incidents.find():
            for event in inc["events"]:
                event_copy = dict(event)
                event_copy["incident_id"] = inc["id"]
                all_events.append(event_copy)

        all_events.sort(key=lambda e: e.get("timestamp", ""))

        for event in all_events:
            await asyncio.sleep(3)  # Simulate real-time feed
            await ws.send_json({
                "type": "new_alert",
                "alert": event,
            })

        while True:
            data = await ws.receive_text()
            await ws.send_json({"type": "pong"})

    except WebSocketDisconnect:
        connected_clients.remove(ws)


async def _broadcast(message: dict):
    """Broadcast a message to all connected WebSocket clients."""
    disconnected = []
    for client in connected_clients:
        try:
            await client.send_json(message)
        except Exception:
            disconnected.append(client)
    for client in disconnected:
        connected_clients.remove(client)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _build_timeline(incidents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Build event timeline for dashboard chart."""
    timeline: Dict[str, Dict[str, Any]] = {}
    for inc in incidents:
        for event in inc["events"]:
            ts = event.get("timestamp", "")
            if ts:
                hour = ts[:16]  # YYYY-MM-DDTHH:MM
                if hour not in timeline:
                    timeline[hour] = {"time": hour, "critical": 0, "high": 0, "medium": 0, "low": 0}
                sev = event.get("severity", "low")
                timeline[hour][sev] = timeline[hour].get(sev, 0) + 1  # type: ignore

    return sorted(timeline.values(), key=lambda t: t["time"])


if __name__ == "__main__":
    import uvicorn  # type: ignore
    uvicorn.run(app, host="0.0.0.0", port=8000)
