
import hmac
import ipaddress
import json
import os
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.alert import Alert
from app.models.incident import Incident
from app.models.investigation import Investigation
from app.models.response_action import ResponseAction


router = APIRouter(
    prefix="/api/v1/response-actions",
    tags=["Human-Gated Response"],
)

ALLOWED_ACTIONS = {
    "block_ip",
    "disable_account",
    "isolate_endpoint",
}

PENDING = "Pending"
APPROVED = "Approved"
REJECTED = "Rejected"
EXECUTED = "Executed"


def utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def authenticate_reviewer(
    authorization: str | None = Header(default=None),
) -> str:
    expected_token = os.getenv("SOC_REVIEWER_TOKEN", "")
    reviewer_id = os.getenv("SOC_REVIEWER_ID", "")

    if not expected_token.strip() or not reviewer_id.strip():
        raise HTTPException(
            status_code=503,
            detail="Reviewer authentication is not configured",
        )

    scheme, separator, supplied_token = (
        authorization or ""
    ).partition(" ")

    if (
        not separator
        or scheme.lower() != "bearer"
        or not hmac.compare_digest(
            supplied_token.strip(),
            expected_token,
        )
    ):
        raise HTTPException(
            status_code=401,
            detail="Valid reviewer authentication is required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return reviewer_id


class ActionProposal(BaseModel):
    incident_id: int = Field(gt=0)
    action_type: Literal[
        "block_ip",
        "disable_account",
        "isolate_endpoint",
    ]
    target: str = Field(min_length=1, max_length=255)

    @field_validator("target")
    @classmethod
    def validate_target(cls, value):
        value = value.strip()
        if not value:
            raise ValueError("Target cannot be blank")
        return value


class RejectionRequest(BaseModel):
    reason: str = Field(min_length=3, max_length=1000)

    @field_validator("reason")
    @classmethod
    def validate_reason(cls, value):
        value = value.strip()
        if len(value) < 3:
            raise ValueError("A rejection reason is required")
        return value


def serialize_action(action: ResponseAction) -> dict:
    return {
        "id": action.id,
        "incident_id": action.incident_id,
        "action_type": action.action_type,
        "target": action.target,
        "status": action.status,
        "approved_by": action.approved_by,
        "approved_at": action.approved_at,
        "rejected_by": action.rejected_by,
        "rejected_at": action.rejected_at,
        "rejection_reason": action.rejection_reason,
        "executed_at": action.executed_at,
        "result": action.result,
        "created_at": action.created_at,
    }


def _load_findings(investigation: Investigation) -> dict:
    try:
        findings = json.loads(investigation.findings or "{}")
    except (TypeError, ValueError):
        raise HTTPException(
            status_code=409,
            detail="Investigation findings are invalid",
        )

    if not isinstance(findings, dict):
        raise HTTPException(
            status_code=409,
            detail="Investigation findings have an invalid format",
        )

    return findings


def _validated_investigation(
    db: Session,
    incident_id: int,
) -> tuple[Investigation, dict, Alert]:
    investigations = (
        db.query(Investigation)
        .filter(Investigation.incident_id == incident_id)
        .order_by(Investigation.id.desc())
        .all()
    )

    for investigation in investigations:
        if investigation.completed_at is None:
            continue

        findings = _load_findings(investigation)
        validation = findings.get("evidence_validation")

        if not isinstance(validation, dict):
            continue

        if findings.get("investigation_status") != "Completed":
            continue

        if findings.get("error"):
            continue

        if validation.get("decision") != "True Positive":
            continue

        if validation.get("evidence_grounded") is not True:
            continue

        unsupported_claims = validation.get("unsupported_claims")
        if not isinstance(unsupported_claims, list) or unsupported_claims:
            continue

        alert_id = findings.get("alert_database_id")
        if not isinstance(alert_id, int) or isinstance(alert_id, bool):
            continue

        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        if alert is None:
            continue

        normalized_alert = findings.get("normalized_alert")
        if not isinstance(normalized_alert, dict):
            continue

        return investigation, findings, alert

    raise HTTPException(
        status_code=409,
        detail=(
            "No completed, error-free, evidence-grounded True Positive "
            "investigation with a linked alert qualifies for this incident"
        ),
    )


def _validate_target(
    action_type: str,
    target: str,
    alert: Alert,
    findings: dict,
) -> str:
    normalized = findings.get("normalized_alert")
    if not isinstance(normalized, dict):
        raise HTTPException(
            status_code=409,
            detail="Investigation has no valid normalized alert",
        )

    if action_type == "block_ip":
        try:
            requested_ip = ipaddress.ip_address(target)
        except ValueError:
            raise HTTPException(
                status_code=422,
                detail="block_ip requires a valid IPv4 or IPv6 address",
            )

        # Restrict blocking to the source IP observed in the linked alert.
        source_ip = alert.source_ip or normalized.get("source_ip")
        if not source_ip:
            raise HTTPException(
                status_code=409,
                detail="The supporting alert has no source IP",
            )

        try:
            evidence_ip = ipaddress.ip_address(str(source_ip).strip())
        except ValueError:
            raise HTTPException(
                status_code=409,
                detail="The supporting alert contains an invalid source IP",
            )

        if requested_ip != evidence_ip:
            raise HTTPException(
                status_code=409,
                detail="Target IP does not match the supporting alert source IP",
            )

        return str(requested_ip)

    if action_type == "disable_account":
        evidence_user = (
            normalized.get("source_user")
            or normalized.get("username")
            or alert.username
        )
        if not evidence_user or target.casefold() != str(evidence_user).strip().casefold():
            raise HTTPException(
                status_code=409,
                detail="Target account does not match the supporting alert",
            )
        return target

    if action_type == "isolate_endpoint":
        evidence_endpoint = (
            normalized.get("agent_name")
            or alert.agent_name
            or normalized.get("agent_id")
            or alert.agent_id
        )
        if (
            not evidence_endpoint
            or target.casefold()
            != str(evidence_endpoint).strip().casefold()
        ):
            raise HTTPException(
                status_code=409,
                detail="Target endpoint does not match the supporting alert",
            )
        return target

    raise HTTPException(
        status_code=400,
        detail="Action type is not permitted",
    )


@router.post("", status_code=201)
def propose_action(
    proposal: ActionProposal,
    db: Session = Depends(get_db),
    reviewer: str = Depends(authenticate_reviewer),
):
    incident = (
        db.query(Incident)
        .filter(Incident.id == proposal.incident_id)
        .first()
    )

    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    if incident.status and incident.status.lower() in {"closed", "resolved"}:
        raise HTTPException(
            status_code=409,
            detail="Cannot propose an action for a closed incident",
        )

    _, findings, alert = _validated_investigation(db, incident.id)
    target = _validate_target(
        proposal.action_type,
        proposal.target,
        alert,
        findings,
    )

    action = ResponseAction(
        incident_id=incident.id,
        action_type=proposal.action_type,
        target=target,
        status=PENDING,
        result=(
            "Awaiting human review. No response executed. "
            f"Proposal created by authenticated reviewer {reviewer}."
        ),
    )

    db.add(action)

    try:
        db.commit()
        db.refresh(action)
    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Unable to save response-action proposal",
        )

    return serialize_action(action)


@router.get("")
def list_actions(
    incident_id: int | None = None,
    db: Session = Depends(get_db),
    reviewer: str = Depends(authenticate_reviewer),
):
    query = db.query(ResponseAction)

    if incident_id is not None:
        query = query.filter(ResponseAction.incident_id == incident_id)

    actions = query.order_by(ResponseAction.id.desc()).all()

    return {
        "reviewer": reviewer,
        "count": len(actions),
        "actions": [serialize_action(action) for action in actions],
    }


@router.post("/{action_id}/approve")
def approve_action(
    action_id: int,
    db: Session = Depends(get_db),
    reviewer: str = Depends(authenticate_reviewer),
):
    action = (
        db.query(ResponseAction)
        .filter(ResponseAction.id == action_id)
        .with_for_update()
        .first()
    )

    if action is None:
        raise HTTPException(status_code=404, detail="Response action not found")

    if action.status != PENDING:
        raise HTTPException(
            status_code=409,
            detail=f"Cannot approve action in status '{action.status}'",
        )

    action.status = APPROVED
    action.approved_by = reviewer
    action.approved_at = utc_now()
    action.rejected_by = None
    action.rejected_at = None
    action.rejection_reason = None
    action.result = "Approved by human reviewer; awaiting simulated execution."

    try:
        db.commit()
        db.refresh(action)
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="Unable to persist approval")

    return serialize_action(action)


@router.post("/{action_id}/reject")
def reject_action(
    action_id: int,
    request: RejectionRequest,
    db: Session = Depends(get_db),
    reviewer: str = Depends(authenticate_reviewer),
):
    action = (
        db.query(ResponseAction)
        .filter(ResponseAction.id == action_id)
        .with_for_update()
        .first()
    )

    if action is None:
        raise HTTPException(status_code=404, detail="Response action not found")

    if action.status != PENDING:
        raise HTTPException(
            status_code=409,
            detail=f"Cannot reject action in status '{action.status}'",
        )

    action.status = REJECTED
    action.rejected_by = reviewer
    action.rejected_at = utc_now()
    action.rejection_reason = request.reason
    action.result = "Rejected by human reviewer. No response executed."

    try:
        db.commit()
        db.refresh(action)
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="Unable to persist rejection")

    return serialize_action(action)


@router.post("/{action_id}/execute")
def execute_action(
    action_id: int,
    db: Session = Depends(get_db),
    reviewer: str = Depends(authenticate_reviewer),
):
    action = (
        db.query(ResponseAction)
        .filter(ResponseAction.id == action_id)
        .with_for_update()
        .first()
    )

    if action is None:
        raise HTTPException(status_code=404, detail="Response action not found")

    if action.status != APPROVED:
        raise HTTPException(
            status_code=409,
            detail="Only human-approved actions can be executed",
        )

    if action.action_type not in ALLOWED_ACTIONS:
        raise HTTPException(status_code=400, detail="Action type is not permitted")

    # Safe prototype executor: it does not modify real security controls.
    action.status = EXECUTED
    action.executed_at = utc_now()
    action.result = (
        f"SIMULATED ONLY: {action.action_type} for {action.target}. "
        "No real system changes were performed. "
        f"Executed by authenticated reviewer {reviewer}."
    )

    try:
        db.commit()
        db.refresh(action)
    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Unable to persist execution result",
        )

    return serialize_action(action)
