from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from src.database import get_db
from src.security.auth import RoleChecker
from src.models.sharing import ThreatSharingPartner, SharedIntelligence, SharingAudit
from src.services.sharing_engine import SharingEngine

router = APIRouter(prefix="/sharing", tags=["Threat Intelligence Sharing"])
allow_all = RoleChecker(["ADMIN", "ANALYST", "VIEWER"])
allow_analyst_admin = RoleChecker(["ADMIN", "ANALYST"])

@router.get("/partners", status_code=status.HTTP_200_OK)
def list_partners(db: Session = Depends(get_db), current_user = Depends(allow_all)):
    return db.query(ThreatSharingPartner).all()

@router.post("/share", status_code=status.HTTP_200_OK)
def share_intelligence_data(partner_id: int, object_type: str, object_id: str, classification_level: str = "TLP:CLEAR", db: Session = Depends(get_db), current_user = Depends(allow_analyst_admin)):
    engine = SharingEngine(db)
    try:
        res = engine.share_intelligence(partner_id, object_type, object_id, classification_level)
        return res
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/history", status_code=status.HTTP_200_OK)
def list_sharing_history(db: Session = Depends(get_db), current_user = Depends(allow_all)):
    return db.query(SharingAudit).all()
