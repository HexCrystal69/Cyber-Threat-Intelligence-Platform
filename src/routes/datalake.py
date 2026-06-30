import datetime
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from src.database import get_db
from src.security.auth import RoleChecker
from src.models.datalake import SecurityEvent, SecurityEventPartition
from src.models.replay import TelemetryReplayJob
from src.services.security_data_lake import SecurityDataLake

router = APIRouter(prefix="/datalake", tags=["Security Data Lake"])
allow_all = RoleChecker(["ADMIN", "ANALYST", "VIEWER"])
allow_analyst_admin = RoleChecker(["ADMIN", "ANALYST"])

@router.get("/events", status_code=status.HTTP_200_OK)
def list_events(db: Session = Depends(get_db), current_user = Depends(allow_all)):
    return db.query(SecurityEvent).all()

@router.get("/partitions", status_code=status.HTTP_200_OK)
def list_partitions(db: Session = Depends(get_db), current_user = Depends(allow_all)):
    return db.query(SecurityEventPartition).all()

@router.get("/search", status_code=status.HTTP_200_OK)
def search_datalake(query: str, db: Session = Depends(get_db), current_user = Depends(allow_all)):
    # simple search
    return db.query(SecurityEvent).filter(SecurityEvent.normalized_json.contains(query)).all()

@router.post("/replay", status_code=status.HTTP_202_ACCEPTED)
def trigger_replay(start_time: datetime.datetime, end_time: datetime.datetime, db: Session = Depends(get_db), current_user = Depends(allow_analyst_admin)):
    engine = SecurityDataLake(db)
    job = engine.run_replay_job(start_time, end_time)
    return job

@router.get("/replay/{id}", status_code=status.HTTP_200_OK)
def get_replay_job(id: int, db: Session = Depends(get_db), current_user = Depends(allow_all)):
    job = db.query(TelemetryReplayJob).filter(TelemetryReplayJob.id == id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Replay job not found")
    return job
