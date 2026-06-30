from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from src.database import get_db
from src.security.auth import RoleChecker
from src.models.hunting_ai import NaturalLanguageQuery
from src.services.query_translation_engine import QueryTranslationEngine

router = APIRouter(prefix="/copilot/query", tags=["Natural Language Threat Hunting"])
allow_all = RoleChecker(["ADMIN", "ANALYST", "VIEWER"])
allow_analyst_admin = RoleChecker(["ADMIN", "ANALYST"])

@router.post("", status_code=status.HTTP_200_OK)
def translate_natural_language_query(query: str, db: Session = Depends(get_db), current_user = Depends(allow_analyst_admin)):
    engine = QueryTranslationEngine(db)
    try:
        return engine.translate_query(query)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/history", status_code=status.HTTP_200_OK)
def get_query_translation_history(db: Session = Depends(get_db), current_user = Depends(allow_all)):
    return db.query(NaturalLanguageQuery).all()
