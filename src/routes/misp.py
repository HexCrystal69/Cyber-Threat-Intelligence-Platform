from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from src.database import get_db
from src.security.auth import RoleChecker
from src.models.misp import MISPInstance, MISPSyncJob
from src.services.misp_engine import MISPEngine

router = APIRouter(prefix="/misp", tags=["MISP Management"])
allow_all = RoleChecker(["ADMIN", "ANALYST", "VIEWER"])
allow_analyst_admin = RoleChecker(["ADMIN", "ANALYST"])

@router.get("", status_code=status.HTTP_200_OK)
def list_instances(db: Session = Depends(get_db), current_user = Depends(allow_all)):
    return db.query(MISPInstance).all()

@router.post("/sync", status_code=status.HTTP_202_ACCEPTED)
def sync_misp_instance(instance_id: int, direction: str = "both", db: Session = Depends(get_db), current_user = Depends(allow_analyst_admin)):
    from src.tasks.sharing_tasks import sync_misp
    task = sync_misp.delay(instance_id, direction)
    return {"task_id": task.id, "status": "PENDING"}

@router.get("/jobs", status_code=status.HTTP_200_OK)
def list_jobs(db: Session = Depends(get_db), current_user = Depends(allow_all)):
    return db.query(MISPSyncJob).all()
