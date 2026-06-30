from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from src.database import get_db
from src.security.auth import RoleChecker
from src.models.ai_usage import AIUsageSnapshot, UserAIUsage

router = APIRouter(prefix="/ai/usage", tags=["AI Cost & Usage Governance"])
allow_all = RoleChecker(["ADMIN", "ANALYST", "VIEWER"])

@router.get("", status_code=status.HTTP_200_OK)
def get_usage_snapshots(db: Session = Depends(get_db), current_user = Depends(allow_all)):
    return db.query(AIUsageSnapshot).all()

@router.get("/users", status_code=status.HTTP_200_OK)
def get_user_usages(db: Session = Depends(get_db), current_user = Depends(allow_all)):
    return db.query(UserAIUsage).all()
