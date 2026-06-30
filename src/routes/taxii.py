from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from src.database import get_db
from src.security.auth import RoleChecker
from src.models.taxii import TAXIICollection, TAXIISyncJob
from src.services.taxii_engine import TAXIIEngine

router = APIRouter(prefix="/taxii", tags=["TAXII Management"])
allow_all = RoleChecker(["ADMIN", "ANALYST", "VIEWER"])
allow_analyst_admin = RoleChecker(["ADMIN", "ANALYST"])

@router.get("/collections", status_code=status.HTTP_200_OK)
def list_collections(db: Session = Depends(get_db), current_user = Depends(allow_all)):
    return db.query(TAXIICollection).all()

@router.post("/sync", status_code=status.HTTP_202_ACCEPTED)
def sync_collection(collection_id: str, sync_type: str = "pull", db: Session = Depends(get_db), current_user = Depends(allow_analyst_admin)):
    from src.tasks.sharing_tasks import sync_taxii
    task = sync_taxii.delay(collection_id, sync_type)
    return {"task_id": task.id, "status": "PENDING"}

@router.get("/jobs", status_code=status.HTTP_200_OK)
def list_jobs(db: Session = Depends(get_db), current_user = Depends(allow_all)):
    return db.query(TAXIISyncJob).all()
