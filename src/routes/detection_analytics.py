from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from src.database import get_db
from src.security.auth import RoleChecker
from src.models.detection_analytics import DetectionAnalyticsSnapshot, AlertFidelityScore
from src.models.detection_health import DetectionHealthSnapshot
from src.models.coverage import DetectionCoverageSnapshot

router = APIRouter(prefix="/detection-analytics", tags=["Detection Analytics"])
allow_all = RoleChecker(["ADMIN", "ANALYST", "VIEWER"])

@router.get("", status_code=status.HTTP_200_OK)
def get_analytics(db: Session = Depends(get_db), current_user = Depends(allow_all)):
    return db.query(DetectionAnalyticsSnapshot).all()

@router.get("/fidelity", status_code=status.HTTP_200_OK)
def get_fidelity_scores(db: Session = Depends(get_db), current_user = Depends(allow_all)):
    return db.query(AlertFidelityScore).all()

@router.get("/coverage", status_code=status.HTTP_200_OK)
def get_coverage_snapshots(db: Session = Depends(get_db), current_user = Depends(allow_all)):
    return db.query(DetectionCoverageSnapshot).all()

@router.get("/trends", status_code=status.HTTP_200_OK)
def get_drift_trends(db: Session = Depends(get_db), current_user = Depends(allow_all)):
    return db.query(DetectionHealthSnapshot).all()

@router.get("/rules/{id}", status_code=status.HTTP_200_OK)
def get_rule_analytics(id: int, db: Session = Depends(get_db), current_user = Depends(allow_all)):
    return db.query(DetectionAnalyticsSnapshot).filter(DetectionAnalyticsSnapshot.detection_rule_id == id).all()
