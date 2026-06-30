from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel
from src.database import get_db
from src.models.alert import SecurityAlert, AlertEvidence, AlertComment
from src.security.auth import RoleChecker, get_current_user
from src.models.user import User

router = APIRouter(prefix="/alerts", tags=["SOC Alerts"])

allow_all = RoleChecker(["ADMIN", "ANALYST", "VIEWER"])
allow_analyst_admin = RoleChecker(["ADMIN", "ANALYST"])

class AlertUpdate(BaseModel):
    status: Optional[str] = None
    severity: Optional[str] = None
    priority: Optional[str] = None

class CommentCreate(BaseModel):
    comment: str

@router.get("", response_model=List[dict])
def list_alerts(db: Session = Depends(get_db), current_user: User = Depends(allow_all)):
    alerts = db.query(SecurityAlert).all()
    return [
        {
            "id": a.id,
            "title": a.title,
            "severity": a.severity,
            "priority": a.priority,
            "status": a.status,
            "confidence_score": a.confidence_score,
            "risk_score": a.risk_score,
            "created_at": a.created_at
        } for a in alerts
    ]

@router.get("/{alert_id}")
def get_alert(alert_id: int, db: Session = Depends(get_db), current_user: User = Depends(allow_all)):
    alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    evidences = db.query(AlertEvidence).filter(AlertEvidence.alert_id == alert_id).all()
    comments = db.query(AlertComment).filter(AlertComment.alert_id == alert_id).all()

    return {
        "alert": {
            "id": alert.id,
            "title": alert.title,
            "severity": alert.severity,
            "priority": alert.priority,
            "status": alert.status,
            "confidence_score": alert.confidence_score,
            "risk_score": alert.risk_score,
            "created_at": alert.created_at
        },
        "evidences": [
            {
                "id": e.id,
                "evidence_type": e.evidence_type,
                "evidence_id": e.evidence_id,
                "evidence_summary": e.evidence_summary
            } for e in evidences
        ],
        "comments": [
            {
                "id": c.id,
                "user_id": c.user_id,
                "comment": c.comment,
                "created_at": c.created_at
            } for c in comments
        ]
    }

@router.patch("/{alert_id}")
def patch_alert(alert_id: int, payload: AlertUpdate, db: Session = Depends(get_db), current_user: User = Depends(allow_analyst_admin)):
    alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    if payload.status:
        alert.status = payload.status
    if payload.severity:
        alert.severity = payload.severity
    if payload.priority:
        alert.priority = payload.priority

    db.commit()
    db.refresh(alert)
    return alert

@router.post("/{alert_id}/comment")
def add_alert_comment(alert_id: int, payload: CommentCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    comment = AlertComment(
        alert_id=alert_id,
        user_id=current_user.id,
        comment=payload.comment
    )
    db.add(comment)
    db.commit()
    db.refresh(comment)
    return comment
