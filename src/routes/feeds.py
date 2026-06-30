from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from src.database import get_db
from src.models.feed import ThreatFeed
from src.schemas.feed import FeedCreate, FeedUpdate, FeedResponse
from src.security.auth import RoleChecker, get_current_user
from src.models.user import User
from src.tasks.ingestion_tasks import ingest_feed
from src.services.audit import log_audit

router = APIRouter(prefix="/feeds", tags=["Threat Feeds"])

# RBAC dependencies
allow_all = RoleChecker(["ADMIN", "ANALYST", "VIEWER"])
allow_analyst_admin = RoleChecker(["ADMIN", "ANALYST"])
allow_admin = RoleChecker(["ADMIN"])

@router.get("", response_model=List[FeedResponse])
def list_feeds(db: Session = Depends(get_db), current_user: User = Depends(allow_all)):
    return db.query(ThreatFeed).all()

@router.post("", response_model=FeedResponse, status_code=status.HTTP_201_CREATED)
def create_feed(feed_in: FeedCreate, db: Session = Depends(get_db), current_user: User = Depends(allow_admin)):
    existing = db.query(ThreatFeed).filter(ThreatFeed.name == feed_in.name).first()
    if existing:
        raise HTTPException(status_code=400, detail="Feed with this name already exists.")
    
    feed = ThreatFeed(**feed_in.model_dump())
    db.add(feed)
    db.commit()
    db.refresh(feed)
    
    log_audit(db, current_user.id, "CREATE", "FEED", str(feed.id))
    return feed

@router.get("/{feed_id}", response_model=FeedResponse)
def get_feed(feed_id: int, db: Session = Depends(get_db), current_user: User = Depends(allow_all)):
    feed = db.query(ThreatFeed).filter(ThreatFeed.id == feed_id).first()
    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")
    return feed

@router.patch("/{feed_id}", response_model=FeedResponse)
def update_feed(feed_id: int, feed_in: FeedUpdate, db: Session = Depends(get_db), current_user: User = Depends(allow_analyst_admin)):
    feed = db.query(ThreatFeed).filter(ThreatFeed.id == feed_id).first()
    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")
    
    update_data = feed_in.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(feed, field, value)
        
    db.commit()
    db.refresh(feed)
    
    log_audit(db, current_user.id, "UPDATE", "FEED", str(feed.id))
    return feed

@router.post("/{feed_id}/ingest", status_code=status.HTTP_202_ACCEPTED)
def trigger_ingest(feed_id: int, db: Session = Depends(get_db), current_user: User = Depends(allow_analyst_admin)):
    feed = db.query(ThreatFeed).filter(ThreatFeed.id == feed_id).first()
    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")
    if not feed.enabled:
        raise HTTPException(status_code=400, detail="Feed is disabled")

    # Start Celery task asynchronously
    task = ingest_feed.delay(feed_id)
    
    log_audit(db, current_user.id, "INGEST_TRIGGER", "FEED", str(feed_id))
    
    return {"job_id": task.id, "status": "PENDING"}
