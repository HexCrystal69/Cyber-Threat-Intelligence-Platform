from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from src.database import get_db
from src.models.job import IngestionJob
from src.schemas.job import JobResponse
from src.security.auth import RoleChecker, get_current_user
from src.models.user import User

router = APIRouter(prefix="/jobs", tags=["Ingestion Jobs"])

# RBAC dependencies
allow_analyst_admin = RoleChecker(["ADMIN", "ANALYST"])

@router.get("", response_model=List[JobResponse])
def list_jobs(db: Session = Depends(get_db), current_user: User = Depends(allow_analyst_admin)):
    return db.query(IngestionJob).order_by(IngestionJob.started_at.desc()).all()

@router.get("/{job_id}", response_model=JobResponse)
def get_job(job_id: str, db: Session = Depends(get_db), current_user: User = Depends(allow_analyst_admin)):
    job = db.query(IngestionJob).filter(IngestionJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Ingestion job not found")
    return job
