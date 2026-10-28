
import json
from datetime import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.alert import Alert
from app.models.incident import Incident
from app.models.investigation import Investigation
from app.models.response_action import ResponseAction
from app.api.response_actions import authenticate_reviewer


router = APIRouter(
    prefix="/api/v1",
    tags=["Dashboard"],
    dependencies=[Depends(authenticate_reviewer)],
)


def serialize_alert(alert: Alert) -> dict:
    """Return dashboard-safe alert fields; omit raw logs and raw JSON."""
    return {
        "id": alert.id,
        "wazuh_alert_id": alert.wazuh_alert_id,
        "timestamp": alert.timestamp.isoformat() if alert.timestamp else None,
        "rule_id": alert.rule_id,
        "rule_level": alert.rule_level,
        "rule_description": alert.rule_description,
        "agent_id": alert.agent_id,
        "agent_name": alert.agent_name,
        "source_ip": alert.source_ip,
        "destination_ip": alert.destination_ip,
        "username": alert.username,
        "decoder": alert.decoder,
        "mitre_attack": alert.mitre_attack,
    }


def parse_findings(value) -> dict:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except (json.JSONDecodeError, TypeError):
            return {}
    return {}


def serialize_investigation(item: Investigation) -> dict:
    findings = parse_findings(item.findings)
    validation = findings.get("evidence_validation") or {}

    return {
        "id": item.id,
        "incident_id": item.incident_id,
        "alert_database_id": findings.get("alert_database_id"),
        "wazuh_alert_id": findings.get("wazuh_alert_id"),
        "investigation_type": item.investigation_type,
        "confidence": item.confidence,
        "started_at": item.started_at.isoformat() if item.started_at else None,
        "completed_at": item.completed_at.isoformat() if item.completed_at else None,
        "decision": validation.get("decision", "Uncertain"),
        "severity": validation.get("severity", "Low"),
        "investigation_status": findings.get("investigation_status", "Unknown"),
        "human_review_required": bool(findings.get("human_review_required", False)),
        "error": findings.get("error"),
    }


@router.get("/dashboard/summary")
def dashboard_summary(db: Session = Depends(get_db)):
    total_alerts = db.query(func.count(Alert.id)).scalar() or 0
    critical_alerts = (
        db.query(func.count(Alert.id))
        .filter(Alert.rule_level >= 12)
        .scalar()
        or 0
    )
    total_incidents = db.query(func.count(Incident.id)).scalar() or 0
    open_incidents = (
        db.query(func.count(Incident.id))
        .filter(func.lower(Incident.status).in_(["open", "in progress"]))
        .scalar()
        or 0
    )
    pending_actions = (
        db.query(func.count(ResponseAction.id))
        .filter(func.lower(ResponseAction.status) == "pending")
        .scalar()
        or 0
    )
    investigations = db.query(func.count(Investigation.id)).scalar() or 0

    # Count completed, error-free investigations that explicitly require
    # human review. Read persisted findings so pagination cannot undercount.
    review_records = (
        db.query(Investigation.findings)
        .filter(Investigation.completed_at.isnot(None))
        .all()
    )

    pending_review = 0
    for (findings_value,) in review_records:
        findings = parse_findings(findings_value)
        if (
            findings.get("human_review_required") is True
            and findings.get("investigation_status") == "Completed"
            and not findings.get("error")
        ):
            pending_review += 1

    return {
        "total_alerts": total_alerts,
        "critical_alerts": critical_alerts,
        "total_incidents": total_incidents,
        "open_incidents": open_incidents,
        "pending_review": pending_review,
        "pending_response_actions": pending_actions,
        "total_investigations": investigations,
    }


@router.get("/alerts")
def list_alerts(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    total = db.query(func.count(Alert.id)).scalar() or 0
    records = (
        db.query(Alert)
        .order_by(Alert.timestamp.desc(), Alert.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    return {
        "count": len(records),
        "total": total,
        "limit": limit,
        "offset": offset,
        "alerts": [serialize_alert(item) for item in records],
    }


@router.get("/incidents")
def list_incidents(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    total = db.query(func.count(Incident.id)).scalar() or 0
    records = (
        db.query(Incident)
        .order_by(Incident.created_at.desc(), Incident.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    return {
        "count": len(records),
        "total": total,
        "limit": limit,
        "offset": offset,
        "incidents": [
            {
                "id": item.id,
                "incident_number": item.incident_number,
                "title": item.title,
                "description": item.description,
                "severity": item.severity,
                "status": item.status,
                "created_at": item.created_at.isoformat() if item.created_at else None,
                "updated_at": item.updated_at.isoformat() if item.updated_at else None,
            }
            for item in records
        ],
    }


@router.get("/investigations")
def list_investigations(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    total = db.query(func.count(Investigation.id)).scalar() or 0
    records = (
        db.query(Investigation)
        .order_by(Investigation.started_at.desc(), Investigation.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    return {
        "count": len(records),
        "total": total,
        "limit": limit,
        "offset": offset,
        "investigations": [serialize_investigation(item) for item in records],
    }
