from flask import Blueprint, jsonify
import json
import os
from datetime import datetime

analytics_bp = Blueprint("analytics", __name__)
LOG_FILE = os.path.join("logs", "generated_logs.ndjson")

@analytics_bp.route("/api/analytics", methods=["GET"])
def get_analytics():
    if not os.path.exists(LOG_FILE):
        return jsonify({
            "total_alerts": 0,
            "critical_alerts": 0,
            "high_severity_rate": 0.0,
            "weekly_alerts": [],
            "latest_threats": [],
            "threat_type_counts": []
        })

    with open(LOG_FILE, "r") as f:
        logs = [json.loads(line) for line in f if line.strip()]

    total = len(logs)
    critical = sum(1 for log in logs if log.get("severity") == "critical" and log.get("status") != "resolved")
    high = sum(1 for log in logs if log.get("severity") == "high")
    rate = round(((critical + high) / total) * 100, 2) if total else 0.0

    week_count = {d: 0 for d in ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]}
    for log in logs:
        try:
            ts = datetime.fromisoformat(log["timestamp"].replace("Z", ""))
            weekday = ts.strftime("%a")
            if weekday in week_count:
                week_count[weekday] += 1
        except Exception:
            continue

    latest_threats = sorted(
        [log for log in logs if log.get("label") != "normal_traffic" and log.get("severity")],
        key=lambda x: x.get("timestamp", ""),
        reverse=True
    )[:5]

    latest_threats_output = [{
        "label": log.get("label", "Unknown"),
        "severity": log.get("severity", "unknown"),
        "date": log.get("timestamp", "")[:10]
    } for log in latest_threats]

    threat_counts = {}
    for log in logs:
        label = log.get("label")
        if label and label != "normal_traffic":
            threat_counts[label] = threat_counts.get(label, 0) + 1

    threat_type_output = [{"label": k, "count": v} for k, v in threat_counts.items()]

    return jsonify({
        "total_alerts": total,
        "critical_alerts": critical,
        "high_severity_rate": rate,
        "weekly_alerts": [{"day": day, "alerts": count} for day, count in week_count.items()],
        "latest_threats": latest_threats_output,
        "threat_type_counts": threat_type_output
    })