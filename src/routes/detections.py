from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from src.database import get_db
from src.models.detection import DetectionRule, DetectionExecution, DetectionRuleSnapshot
from src.security.auth import RoleChecker, get_current_user
from src.models.user import User
from src.tasks.detection_tasks import execute_all_detection_rules

router = APIRouter(prefix="/detections", tags=["Detection Engineering"])

allow_all = RoleChecker(["ADMIN", "ANALYST", "VIEWER"])
allow_analyst_admin = RoleChecker(["ADMIN", "ANALYST"])

@router.post("/run", status_code=status.HTTP_202_ACCEPTED)
def run_detections(db: Session = Depends(get_db), current_user: User = Depends(allow_analyst_admin)):
    task = execute_all_detection_rules.delay()
    return {"job_id": task.id, "status": "PENDING"}

@router.get("", response_model=List[dict])
def list_detection_rules(db: Session = Depends(get_db), current_user: User = Depends(allow_all)):
    rules = db.query(DetectionRule).all()
    return [
        {
            "id": r.id,
            "name": r.name,
            "rule_type": r.rule_type,
            "enabled": r.enabled,
            "severity": r.severity,
            "version": r.version,
            "author": r.author,
            "status": r.status
        } for r in rules
    ]

@router.get("/{rule_id}")
def get_detection_rule(rule_id: int, db: Session = Depends(get_db), current_user: User = Depends(allow_all)):
    rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Detection rule not found")

    snapshots = db.query(DetectionRuleSnapshot).filter(
        DetectionRuleSnapshot.detection_rule_id == rule_id
    ).all()

    executions = db.query(DetectionExecution).filter(
        DetectionExecution.detection_rule_id == rule_id
    ).all()

    return {
        "rule": {
            "id": rule.id,
            "name": rule.name,
            "rule_type": rule.rule_type,
            "enabled": rule.enabled,
            "severity": rule.severity,
            "version": rule.version,
            "author": rule.author,
            "status": rule.status,
            "created_at": rule.created_at,
            "updated_at": rule.updated_at
        },
        "snapshots": [
            {
                "id": s.id,
                "version": s.version,
                "created_at": s.created_at
            } for s in snapshots
        ],
        "executions": [
            {
                "id": e.id,
                "status": e.status,
                "matched_records": e.matched_records,
                "execution_runtime_ms": e.execution_runtime_ms,
                "started_at": e.started_at
            } for e in executions
        ]
    }
