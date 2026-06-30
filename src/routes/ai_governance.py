from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from src.database import get_db
from src.security.auth import RoleChecker
from src.models.ai_governance import ModelRegistry, AIValidationRun, PromptExecution

router = APIRouter(prefix="/ai", tags=["AI Model Governance & Audits"])
allow_all = RoleChecker(["ADMIN", "ANALYST", "VIEWER"])

@router.get("/models", status_code=status.HTTP_200_OK)
def list_models(db: Session = Depends(get_db), current_user = Depends(allow_all)):
    return db.query(ModelRegistry).all()

@router.get("/validations", status_code=status.HTTP_200_OK)
def list_validations(db: Session = Depends(get_db), current_user = Depends(allow_all)):
    return db.query(AIValidationRun).all()

@router.get("/executions", status_code=status.HTTP_200_OK)
def list_prompt_executions(db: Session = Depends(get_db), current_user = Depends(allow_all)):
    return db.query(PromptExecution).all()
