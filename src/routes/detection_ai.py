from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from src.database import get_db
from src.security.auth import RoleChecker
from src.models.detection_ai import DetectionSuggestion
from src.services.detection_ai_engine import DetectionAIEngine

router = APIRouter(prefix="/detection-ai", tags=["Detection Engineering AI"])
allow_all = RoleChecker(["ADMIN", "ANALYST", "VIEWER"])
allow_analyst_admin = RoleChecker(["ADMIN", "ANALYST"])

@router.post("/suggest", status_code=status.HTTP_200_OK)
def suggest_detection_rule(technique_id: str, rule_type: str = "SIGMA", db: Session = Depends(get_db), current_user = Depends(allow_analyst_admin)):
    engine = DetectionAIEngine(db)
    return engine.suggest_rule(technique_id, rule_type)

@router.get("/suggestions", status_code=status.HTTP_200_OK)
def list_suggestions(db: Session = Depends(get_db), current_user = Depends(allow_all)):
    return db.query(DetectionSuggestion).all()
