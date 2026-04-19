"""
Blue Team Co-Pilot — Threat Registration Module
Manual threat/event registration stored in MongoDB.
"""

from datetime import datetime
from typing import Optional
from fastapi import APIRouter, HTTPException  # type: ignore
from pydantic import BaseModel  # type: ignore
import motor.motor_asyncio  # type: ignore
import os

# ─── MongoDB ──────────────────────────────────────────────────────────────────
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_URI)
db = client["blue_team_copilot"]
threats_collection = db["threats"]

# ─── Pydantic Models ─────────────────────────────────────────────────────────
class ThreatCreate(BaseModel):
    title: str
    event_type: str
    severity: str  # low, medium, high, critical
    source: str  # firewall, edr, waf, cloud, identity, dlp
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    hostname: Optional[str] = None
    user: Optional[str] = None
    description: str

# ─── Router ───────────────────────────────────────────────────────────────────
threats_router = APIRouter(prefix="/api/threats", tags=["threats"])

@threats_router.get("")
async def list_threats():
    """List all manually registered threats."""
    threats = []
    cursor = threats_collection.find().sort("created_at", -1)
    async for doc in cursor:
        doc["_id"] = str(doc["_id"])
        threats.append(doc)
    return {"total": len(threats), "threats": threats}


@threats_router.post("")
async def create_threat(req: ThreatCreate):
    """Register a new threat manually."""
    if req.severity not in ("low", "medium", "high", "critical"):
        raise HTTPException(status_code=400, detail="Severity must be low, medium, high, or critical")

    doc = {
        "title": req.title,
        "event_type": req.event_type,
        "severity": req.severity,
        "source": req.source,
        "src_ip": req.src_ip,
        "dst_ip": req.dst_ip,
        "dst_port": req.dst_port,
        "protocol": req.protocol,
        "hostname": req.hostname,
        "user": req.user,
        "description": req.description,
        "status": "open",
        "created_at": datetime.utcnow().isoformat() + "Z",
    }
    result = await threats_collection.insert_one(doc)
    doc["_id"] = str(result.inserted_id)
    return {"message": "Threat registered successfully", "threat": doc}


@threats_router.delete("/{threat_id}")
async def delete_threat(threat_id: str):
    """Delete a registered threat."""
    from bson import ObjectId  # type: ignore
    result = await threats_collection.delete_one({"_id": ObjectId(threat_id)})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Threat not found")
    return {"message": "Threat deleted"}
