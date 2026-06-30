from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from pydantic import BaseModel
from src.database import get_db
from src.models.playbook import ResponsePlaybook, PlaybookStep
from src.security.auth import RoleChecker, get_current_user
from src.models.user import User
from src.tasks.case_tasks import execute_playbook_task

router = APIRouter(prefix="/playbooks", tags=["Response Playbooks"])

allow_all = RoleChecker(["ADMIN", "ANALYST", "VIEWER"])
allow_analyst_admin = RoleChecker(["ADMIN", "ANALYST"])

class PlaybookCreate(BaseModel):
    name: str
    description: str
    severity: str

class StepCreate(BaseModel):
    step_order: int
    action_type: str
    action_definition: dict

class PlaybookExecuteRequest(BaseModel):
    target_ioc_id: int

@router.get("", response_model=List[dict])
def list_playbooks(db: Session = Depends(get_db), current_user: User = Depends(allow_all)):
    playbooks = db.query(ResponsePlaybook).all()
    return [
        {
            "id": p.id,
            "name": p.name,
            "description": p.description,
            "severity": p.severity,
            "enabled": p.enabled,
            "created_at": p.created_at
        } for p in playbooks
    ]

@router.post("", status_code=status.HTTP_201_CREATED)
def create_playbook(payload: PlaybookCreate, db: Session = Depends(get_db), current_user: User = Depends(allow_analyst_admin)):
    playbook = ResponsePlaybook(
        name=payload.name,
        description=payload.description,
        severity=payload.severity
    )
    db.add(playbook)
    db.commit()
    db.refresh(playbook)
    return playbook

@router.post("/{playbook_id}/execute", status_code=status.HTTP_202_ACCEPTED)
def execute_playbook_endpoint(playbook_id: int, payload: PlaybookExecuteRequest, db: Session = Depends(get_db), current_user: User = Depends(allow_analyst_admin)):
    playbook = db.query(ResponsePlaybook).filter(ResponsePlaybook.id == playbook_id).first()
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")

    task = execute_playbook_task.delay(playbook_id, payload.target_ioc_id, current_user.id)
    return {"job_id": task.id, "status": "PENDING"}
