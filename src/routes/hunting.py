from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from pydantic import BaseModel
from src.database import get_db
from src.models.hunting import HuntingQuery, HuntingExecution, HuntingResult
from src.security.auth import RoleChecker, get_current_user
from src.models.user import User
from src.tasks.detection_tasks import execute_hunting_query

router = APIRouter(prefix="/hunting", tags=["Threat Hunting"])

allow_all = RoleChecker(["ADMIN", "ANALYST", "VIEWER"])
allow_analyst_admin = RoleChecker(["ADMIN", "ANALYST"])

class HuntRunRequest(BaseModel):
    query_id: int

@router.post("/run", status_code=status.HTTP_202_ACCEPTED)
def run_hunting_query(payload: HuntRunRequest, db: Session = Depends(get_db), current_user: User = Depends(allow_analyst_admin)):
    task = execute_hunting_query.delay(payload.query_id)
    return {"job_id": task.id, "status": "PENDING"}

@router.get("", response_model=List[dict])
def list_hunting_queries(db: Session = Depends(get_db), current_user: User = Depends(allow_all)):
    queries = db.query(HuntingQuery).all()
    return [
        {
            "id": q.id,
            "name": q.name,
            "description": q.description,
            "query_type": q.query_type,
            "tags": q.tags,
            "enabled": q.enabled,
            "created_at": q.created_at
        } for q in queries
    ]

@router.get("/{query_id}")
def get_hunting_query(query_id: int, db: Session = Depends(get_db), current_user: User = Depends(allow_all)):
    query = db.query(HuntingQuery).filter(HuntingQuery.id == query_id).first()
    if not query:
        raise HTTPException(status_code=404, detail="Hunting query not found")

    executions = db.query(HuntingExecution).filter(
        HuntingExecution.hunting_query_id == query_id
    ).all()

    return {
        "query": {
            "id": query.id,
            "name": query.name,
            "description": query.description,
            "query_type": query.query_type,
            "query_definition": query.query_definition,
            "tags": query.tags,
            "attack_technique_id": query.attack_technique_id,
            "author": query.author,
            "version": query.version,
            "enabled": query.enabled,
            "created_at": query.created_at
        },
        "executions": [
            {
                "id": e.id,
                "status": e.status,
                "matches_found": e.matches_found,
                "runtime_ms": e.runtime_ms,
                "started_at": e.started_at
            } for e in executions
        ]
    }
