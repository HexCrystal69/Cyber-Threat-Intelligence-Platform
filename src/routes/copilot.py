from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from src.database import get_db
from src.security.auth import RoleChecker
from src.models.copilot import CopilotSession
from src.services.copilot_engine import CopilotEngine

router = APIRouter(prefix="/copilot", tags=["AI Security Copilot"])
allow_all = RoleChecker(["ADMIN", "ANALYST", "VIEWER"])
allow_analyst_admin = RoleChecker(["ADMIN", "ANALYST"])

@router.post("/chat", status_code=status.HTTP_200_OK)
def copilot_chat(session_id: int, user_message: str, prompt_template_name: str = None, db: Session = Depends(get_db), current_user = Depends(allow_analyst_admin)):
    engine = CopilotEngine(db)
    try:
        return engine.chat(session_id, user_message, prompt_template_name)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/sessions", status_code=status.HTTP_200_OK)
def list_sessions(db: Session = Depends(get_db), current_user = Depends(allow_all)):
    return db.query(CopilotSession).all()

@router.get("/sessions/{id}", status_code=status.HTTP_200_OK)
def get_session(id: int, db: Session = Depends(get_db), current_user = Depends(allow_all)):
    sess = db.query(CopilotSession).filter(CopilotSession.id == id).first()
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")
    return sess
