from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from src.database import get_db
from src.security.auth import RoleChecker, get_current_user
from src.models.response import AutomatedResponse, ResponseExecution
from src.services.response_engine import ResponseEngine

router = APIRouter(prefix="/responses", tags=["SOAR Response Management"])
allow_all = RoleChecker(["ADMIN", "ANALYST", "VIEWER"])
allow_analyst_admin = RoleChecker(["ADMIN", "ANALYST"])
allow_admin = RoleChecker(["ADMIN"])

@router.get("", status_code=status.HTTP_200_OK)
def list_responses(db: Session = Depends(get_db), current_user = Depends(allow_all)):
    return db.query(AutomatedResponse).all()

@router.post("/execute", status_code=status.HTTP_202_ACCEPTED)
def execute_response_action(response_id: int, target_type: str, target_id: str, db: Session = Depends(get_db), current_user = Depends(allow_analyst_admin)):
    from src.tasks.response_tasks import execute_response
    task = execute_response.delay(response_id, target_type, target_id)
    return {"task_id": task.id, "status": "PENDING"}

@router.get("/executions", status_code=status.HTTP_200_OK)
def list_executions(db: Session = Depends(get_db), current_user = Depends(allow_all)):
    return db.query(ResponseExecution).all()

@router.post("/approve", status_code=status.HTTP_200_OK)
def approve_response_execution(execution_id: int, db: Session = Depends(get_db), current_user = Depends(allow_admin)):
    engine = ResponseEngine(db)
    try:
        res = engine.approve_response(execution_id, approver_name=current_user.email)
        return res
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/rollback", status_code=status.HTTP_200_OK)
def rollback_response_execution(execution_id: int, db: Session = Depends(get_db), current_user = Depends(allow_admin)):
    engine = ResponseEngine(db)
    try:
        res = engine.rollback_response(execution_id)
        return res
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
