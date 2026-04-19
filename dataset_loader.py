"""
Real-Time SIEM Dataset Loader
Fetches real security event data from the Hugging Face Advanced SIEM Dataset
(darkknight25/Advanced_SIEM_Dataset — 100K records) and converts it into the
format expected by the Blue Team Co-Pilot detection pipeline.

Dataset: https://huggingface.co/datasets/darkknight25/Advanced_SIEM_Dataset
License: MIT
"""

import httpx  # type: ignore
import json
import os
import re
import random
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

# ─── Configuration ────────────────────────────────────────────────────────────
HF_DATASET_API = "https://datasets-server.huggingface.co/rows"
DATASET_NAME = "darkknight25/Advanced_SIEM_Dataset"
DEFAULT_SAMPLE_SIZE = 200  # Fetch 200 records for a rich dataset

# Maps HF event_type to our internal event types
EVENT_TYPE_MAP = {
    "firewall": "connection_attempt",
    "ids_alert": "sql_injection_attempt",
    "auth": "suspicious_login",
    "endpoint": "process_execution",
    "network": "connection_attempt",
    "cloud": "iam_change",
    "iot": "c2_communication",
    "ai": "dns_tunneling",
}

# Maps HF alert_type to more specific internal types
ALERT_TYPE_MAP = {
    "Zero-Day Exploit": "rce_attempt",
    "Credential Stuffing": "brute_force",
    "DDoS": "connection_attempt",
    "SQL Injection": "sql_injection_attempt",
    "XSS": "sql_injection_attempt",
    "Ransomware": "ransomware",
    "Phishing": "suspicious_login",
    "Data Exfiltration": "data_exfiltration",
    "Insider Threat": "credential_dump",
    "Brute Force": "brute_force",
    "DNS Tunneling": "dns_tunneling",
    "Advanced Persistent Threat": "lateral_movement",
    "Malware": "malware_detected",
    "Command and Control": "c2_communication",
    "Beaconing": "c2_communication",
    "Man-in-the-Middle": "credential_dump",
    "Buffer Overflow": "rce_attempt",
    "Privilege Escalation": "credential_dump",
    "Port Scan": "connection_attempt",
    "Cryptojacking": "crypto_mining",
}

# Maps HF action to internal types (for auth/endpoint events)
ACTION_TYPE_MAP = {
    "login_failure": "brute_force",
    "login_success": "suspicious_login",
    "file_access": "data_staging",
    "file_modify": "file_creation",
    "file_delete": "ransomware",
    "registry_modify": "persistence",
    "process_start": "process_execution",
    "process_stop": "process_execution",
    "privilege_escalation": "credential_dump",
    "mfa_bypass": "mfa_bypass",
    "password_change": "credential_dump",
    "role_change": "iam_change",
    "side_channel": "c2_communication",
    "data_leak": "data_exfiltration",
    "config_change": "iam_change",
}

# Maps HF severity to our system
SEVERITY_MAP = {
    "info": "low",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
    "emergency": "critical",
}

# Maps HF source to our data source categories
SOURCE_MAP = {
    "Splunk": "edr",
    "QRadar": "edr",
    "ArcSight": "firewall",
    "Microsoft Sentinel": "edr",
    "Elastic SIEM": "edr",
    "AlienVault": "identity",
    "LogRhythm": "edr",
    "Suricata": "firewall",
    "Snort": "firewall",
    "CrowdStrike": "edr",
    "Carbon Black": "edr",
    "SentinelOne": "edr",
    "Palo Alto": "firewall",
    "Fortinet": "firewall",
}

# Simulated threat intel for enrichment of real IPs
KNOWN_THREAT_IPS = {}


def _extract_source_category(source_str: str) -> str:
    """Extract source category from HF source string like 'Splunk v9.0.2'."""
    for key, val in SOURCE_MAP.items():
        if key.lower() in source_str.lower():
            return val
    return "edr"


def _extract_mitre_technique(additional_info: str) -> Optional[str]:
    """Extract MITRE technique from additional_info field."""
    if not additional_info:
        return None
    match = re.search(r"T\d{4}(?:\.\d{3})?", additional_info)
    return match.group(0) if match else None


def _determine_event_type(record: Dict[str, Any]) -> str:
    """Determine the internal event type from a HF dataset record."""
    # First check alert_type (most specific for IDS alerts)
    alert_type = record.get("alert_type")
    if alert_type and alert_type in ALERT_TYPE_MAP:
        return ALERT_TYPE_MAP[alert_type]

    # Then check action (for auth/endpoint events)
    action = record.get("action")
    if action and action in ACTION_TYPE_MAP:
        return ACTION_TYPE_MAP[action]

    # Fall back to event_type mapping
    event_type = record.get("event_type", "")
    return EVENT_TYPE_MAP.get(event_type, "connection_attempt")


def _generate_hostname(record: Dict[str, Any]) -> Optional[str]:
    """Generate a realistic hostname based on the event type."""
    event_type = record.get("event_type", "")
    action = record.get("action", "")
    user = record.get("user")

    if event_type == "endpoint" and user:
        return f"ws-{user[:8]}-01"
    if event_type == "cloud":
        svc = record.get("cloud_service", "aws")
        return f"{svc}-instance-01" if svc else "cloud-srv-01"
    if event_type == "iot":
        device = record.get("device_type", "sensor")
        return f"iot-{device.lower()}-01" if device else "iot-device-01"
    if event_type == "auth":
        return "dc-auth-01"
    if event_type == "firewall" or event_type == "network":
        return "fw-edge-01"
    if event_type == "ids_alert":
        return "ids-sensor-01"
    return None


def _convert_record(record: Dict[str, Any], idx: int) -> Dict[str, Any]:
    """Convert a single HF dataset record to our internal format."""
    # Extract fields
    event_type = _determine_event_type(record)
    severity = SEVERITY_MAP.get(record.get("severity", "low"), "low")
    source = _extract_source_category(record.get("source", ""))
    timestamp = record.get("timestamp", "")

    # Handle timestamp
    if isinstance(timestamp, str):
        if not timestamp.endswith("Z") and "+" not in timestamp:
            timestamp = timestamp + "Z"
    else:
        timestamp = datetime.utcnow().isoformat() + "Z"

    src_ip = record.get("src_ip")
    dst_ip = record.get("dst_ip")
    if dst_ip == "N/A":
        dst_ip = None

    hostname = _generate_hostname(record)
    user = record.get("user")
    description = record.get("description", "Security event detected")
    raw_log = record.get("raw_log", "")

    # Extract metadata
    metadata = record.get("advanced_metadata", {}) or {}
    risk_score = metadata.get("risk_score", 50.0)
    confidence = metadata.get("confidence", 0.5)
    geo_location = metadata.get("geo_location", "Unknown")

    # Extract MITRE technique
    additional_info = record.get("additional_info", "")
    mitre_technique = _extract_mitre_technique(additional_info)

    # Build port info
    dst_port = record.get("dst_port")
    protocol = record.get("protocol")

    # Determine protocol from event type if not present
    if not protocol:
        if event_type in ("connection_attempt", "data_exfiltration"):
            protocol = "TCP"
        elif event_type in ("dns_tunneling",):
            protocol = "DNS"
        elif event_type in ("suspicious_login", "brute_force"):
            protocol = "HTTPS"

    # Build the converted event
    event = {
        "id": f"EVT-{idx + 1:04d}",
        "timestamp": timestamp,
        "source": source,
        "source_system": record.get("source", "Unknown"),
        "event_type": event_type,
        "severity": severity,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "protocol": protocol,
        "user": user,
        "hostname": hostname,
        "description": description,
        "raw_log": raw_log,
        # Extra metadata from real dataset
        "risk_score": round(risk_score, 2),
        "confidence": round(confidence, 2),
        "geo_location": geo_location,
    }

    # Add behavioral analytics if present
    behavioral = record.get("behavioral_analytics")
    if behavioral:
        event["behavioral_analytics"] = {
            "baseline_deviation": behavioral.get("baseline_deviation", 0),
            "entropy": behavioral.get("entropy", 0),
            "frequency_anomaly": behavioral.get("frequency_anomaly", False),
            "sequence_anomaly": behavioral.get("sequence_anomaly", False),
        }

    # Add MITRE info if found
    if mitre_technique:
        event["mitre_technique_id"] = mitre_technique

    # Add alert category if present
    if record.get("alert_type"):
        event["alert_type"] = record["alert_type"]
    if record.get("category"):
        event["alert_category"] = record["category"]

    return event


async def fetch_real_dataset(sample_size: int = DEFAULT_SAMPLE_SIZE) -> List[Dict[str, Any]]:
    """
    Fetch real security events from the Hugging Face Advanced SIEM Dataset.
    Returns converted events in our internal format.
    """
    events = []
    # Fetch from multiple offsets to get diverse data
    batch_size = min(100, sample_size)
    offsets = []

    # Get records from different parts of the 100K dataset
    total_records = 100000
    num_batches = max(1, sample_size // batch_size)
    for i in range(num_batches):
        offset = random.randint(0, total_records - batch_size)
        offsets.append(offset)

    async with httpx.AsyncClient(timeout=30.0) as client:
        for offset in offsets:
            try:
                resp = await client.get(
                    HF_DATASET_API,
                    params={
                        "dataset": DATASET_NAME,
                        "config": "default",
                        "split": "train",
                        "offset": offset,
                        "length": batch_size,
                    },
                )
                if resp.status_code == 200:
                    data = resp.json()
                    rows = data.get("rows", [])
                    for row_data in rows:
                        record = row_data.get("row", {})
                        events.append(record)
            except Exception as e:
                print(f"⚠️ Error fetching dataset batch at offset {offset}: {e}")
                continue

    # Convert all records to our format
    converted = []
    for idx, record in enumerate(events[:sample_size]):
        try:
            converted.append(_convert_record(record, idx))
        except Exception as e:
            print(f"⚠️ Skipping record {idx}: {e}")
            continue

    # Sort by timestamp
    converted.sort(key=lambda e: e.get("timestamp", ""))

    print(f"✅ Loaded {len(converted)} real SIEM events from Hugging Face dataset")
    return converted


def fetch_real_dataset_sync(sample_size: int = DEFAULT_SAMPLE_SIZE) -> List[Dict[str, Any]]:
    """Synchronous wrapper for fetching the real dataset."""
    import asyncio
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # If we're already in an async context, create a new thread
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(asyncio.run, fetch_real_dataset(sample_size))
                return future.result()
        return loop.run_until_complete(fetch_real_dataset(sample_size))
    except RuntimeError:
        return asyncio.run(fetch_real_dataset(sample_size))


# ─── Dataset Stats ────────────────────────────────────────────────────────────
def get_dataset_info() -> Dict[str, Any]:
    """Return metadata about the dataset being used."""
    return {
        "name": "Advanced SIEM Dataset",
        "source": "Hugging Face (darkknight25/Advanced_SIEM_Dataset)",
        "total_records": 100000,
        "format": "JSON Lines (.jsonl)",
        "license": "MIT",
        "features": [
            "Firewall logs", "IDS alerts", "Authentication events",
            "Endpoint activities", "Network traffic", "Cloud operations",
            "IoT device events", "AI system interactions",
        ],
        "includes": [
            "MITRE ATT&CK technique mapping",
            "Behavioral analytics (10% of records)",
            "Advanced metadata with geo-location",
            "Risk scores and confidence levels",
            "CEF-formatted raw logs",
        ],
        "url": f"https://huggingface.co/datasets/{DATASET_NAME}",
    }
