from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from src.database import get_db
from src.security.auth import RoleChecker
from src.models.rag import KnowledgeDocument, RetrievalExecution

router = APIRouter(prefix="/rag", tags=["RAG Evidence Registry"])
allow_all = RoleChecker(["ADMIN", "ANALYST", "VIEWER"])
allow_analyst_admin = RoleChecker(["ADMIN", "ANALYST"])

@router.post("/reindex", status_code=status.HTTP_202_ACCEPTED)
def reindex_rag_documents(db: Session = Depends(get_db), current_user = Depends(allow_analyst_admin)):
    from src.tasks.rag_tasks import reindex_documents
    task = reindex_documents.delay()
    return {"task_id": task.id, "status": "PENDING"}

@router.get("/documents", status_code=status.HTTP_200_OK)
def list_documents(db: Session = Depends(get_db), current_user = Depends(allow_all)):
    return db.query(KnowledgeDocument).all()

@router.get("/retrievals", status_code=status.HTTP_200_OK)
def list_retrieval_executions(db: Session = Depends(get_db), current_user = Depends(allow_all)):
    return db.query(RetrievalExecution).all()
