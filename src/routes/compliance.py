from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from src.database import get_db
from src.security.auth import RoleChecker
from src.models.compliance import SecurityControl, ComplianceSnapshot
from src.services.compliance_engine import ComplianceEngine

router = APIRouter(prefix="/compliance", tags=["Compliance Reporting"])
allow_all = RoleChecker(["ADMIN", "ANALYST", "VIEWER"])
allow_analyst_admin = RoleChecker(["ADMIN", "ANALYST"])

@router.get("", status_code=status.HTTP_200_OK)
def get_compliance_status(db: Session = Depends(get_db), current_user = Depends(allow_all)):
    return db.query(SecurityControl).all()

@router.get("/frameworks", status_code=status.HTTP_200_OK)
def list_frameworks(db: Session = Depends(get_db), current_user = Depends(allow_all)):
    return ["NIST_CSF", "CIS_CONTROLS", "ISO_27001", "MITRE_ATTACK"]

@router.get("/snapshots", status_code=status.HTTP_200_OK)
def get_snapshots(db: Session = Depends(get_db), current_user = Depends(allow_all)):
    return db.query(ComplianceSnapshot).all()

@router.post("/calculate", status_code=status.HTTP_200_OK)
def run_compliance_calculation(framework: str, db: Session = Depends(get_db), current_user = Depends(allow_analyst_admin)):
    engine = ComplianceEngine(db)
    return engine.calculate_compliance(framework)
