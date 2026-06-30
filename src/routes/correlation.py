from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from src.database import get_db
from src.models.correlation import CorrelationGroup, CorrelationRun
from src.security.auth import RoleChecker, get_current_user
from src.models.user import User
from src.services.correlation_engine import CorrelationEngine

router = APIRouter(prefix="/correlation", tags=["Correlation"])

allow_all = RoleChecker(["ADMIN", "ANALYST", "VIEWER"])
allow_analyst_admin = RoleChecker(["ADMIN", "ANALYST"])

@router.post("/run", status_code=status.HTTP_202_ACCEPTED)
def run_correlation(db: Session = Depends(get_db), current_user: User = Depends(allow_analyst_admin)):
    engine = CorrelationEngine(db)
    run_id = engine.run_correlation()
    return {"correlation_run_id": run_id, "status": "SUCCESS"}

@router.get("", response_model=List[dict])
def list_correlation_groups(db: Session = Depends(get_db), current_user: User = Depends(allow_all)):
    groups = db.query(CorrelationGroup).all()
    # Simple dict formatting
    return [
        {
            "id": g.id,
            "name": g.name,
            "severity": g.severity,
            "confidence_score": g.confidence_score,
            "ioc_count": g.ioc_count,
            "created_at": g.created_at
        } for g in groups
    ]

@router.get("/{group_id}")
def get_correlation_group(group_id: int, db: Session = Depends(get_db), current_user: User = Depends(allow_all)):
    group = db.query(CorrelationGroup).filter(CorrelationGroup.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Correlation group not found")
        
    from src.models.correlation import CorrelationEvidence
    evidences = db.query(CorrelationEvidence).filter(CorrelationEvidence.correlation_group_id == group_id).all()
    
    return {
        "id": group.id,
        "name": group.name,
        "severity": group.severity,
        "confidence_score": group.confidence_score,
        "ioc_count": group.ioc_count,
        "created_at": group.created_at,
        "evidences": [
            {
                "ioc_id": e.ioc_id,
                "evidence_type": e.evidence_type,
                "evidence_value": e.evidence_value,
                "confidence": e.confidence,
                "weight": e.weight,
                "score_contribution": e.score_contribution
            } for e in evidences
        ]
    }
