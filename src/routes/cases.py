from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel
from src.database import get_db
from src.models.case import InvestigationCase, CaseAlert, CaseEvidence
from src.security.auth import RoleChecker, get_current_user
from src.models.user import User
from src.services.case_engine import CaseEngine

router = APIRouter(prefix="/cases", tags=["SOC Investigation Cases"])

allow_all = RoleChecker(["ADMIN", "ANALYST", "VIEWER"])
allow_analyst_admin = RoleChecker(["ADMIN", "ANALYST"])

class CaseCreate(BaseModel):
    title: str
    description: str
    severity: str

class CaseUpdate(BaseModel):
    status: Optional[str] = None
    severity: Optional[str] = None
    owner: Optional[str] = None

@router.post("")
def create_case_endpoint(payload: CaseCreate, db: Session = Depends(get_db), current_user: User = Depends(allow_analyst_admin)):
    engine = CaseEngine(db)
    case = engine.create_case(
        title=payload.title,
        description=payload.description,
        severity=payload.severity,
        user_id=current_user.id
    )
    db.refresh(case)
    return case

@router.get("", response_model=List[dict])
def list_cases(db: Session = Depends(get_db), current_user: User = Depends(allow_all)):
    cases = db.query(InvestigationCase).all()
    return [
        {
            "id": c.id,
            "title": c.title,
            "description": c.description,
            "severity": c.severity,
            "status": c.status,
            "owner": c.owner,
            "created_at": c.created_at,
            "closed_at": c.closed_at
        } for c in cases
    ]

@router.get("/{case_id}")
def get_case(case_id: int, db: Session = Depends(get_db), current_user: User = Depends(allow_all)):
    case = db.query(InvestigationCase).filter(InvestigationCase.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    alerts = db.query(CaseAlert).filter(CaseAlert.case_id == case_id).all()
    evidences = db.query(CaseEvidence).filter(CaseEvidence.case_id == case_id).all()

    return {
        "case": {
            "id": case.id,
            "title": case.title,
            "description": case.description,
            "severity": case.severity,
            "status": case.status,
            "owner": case.owner,
            "created_at": case.created_at,
            "closed_at": case.closed_at
        },
        "alert_ids": [ca.alert_id for ca in alerts],
        "evidences": [
            {
                "id": e.id,
                "evidence_type": e.evidence_type,
                "evidence_id": e.evidence_id
            } for e in evidences
        ]
    }

@router.patch("/{case_id}")
def patch_case(case_id: int, payload: CaseUpdate, db: Session = Depends(get_db), current_user: User = Depends(allow_analyst_admin)):
    engine = CaseEngine(db)
    try:
        if payload.status:
            engine.update_case_status(case_id, payload.status, current_user.id)
        
        case = db.query(InvestigationCase).filter(InvestigationCase.id == case_id).first()
        if not case:
            raise HTTPException(status_code=404, detail="Case not found")

        if payload.severity:
            case.severity = payload.severity
        if payload.owner:
            case.owner = payload.owner

        db.commit()
        db.refresh(case)
        return case
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
