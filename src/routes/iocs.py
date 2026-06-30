import os
import shutil
import uuid
import datetime
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import and_
from typing import List, Optional
from src.database import get_db
from src.models.ioc import IOC, IOCMetadata
from src.models.feed import ThreatFeed
from src.schemas.ioc import IOCResponse
from src.security.auth import RoleChecker, get_current_user
from src.models.user import User
from src.tasks.ingestion_tasks import bulk_upload_iocs
from src.services.audit import log_audit

router = APIRouter(prefix="/iocs", tags=["IOC Management"])

# RBAC dependencies
allow_all = RoleChecker(["ADMIN", "ANALYST", "VIEWER"])
allow_analyst_admin = RoleChecker(["ADMIN", "ANALYST"])

MAX_UPLOAD_SIZE = 50 * 1024 * 1024  # 50 MB

@router.get("", response_model=List[IOCResponse])
def search_iocs(
    indicator_type: Optional[str] = Query(None, alias="type"),
    severity: Optional[str] = None,
    source: Optional[str] = None,
    status: Optional[str] = None,
    start_date: Optional[datetime.datetime] = None,
    end_date: Optional[datetime.datetime] = None,
    query: Optional[str] = None,  # search text query
    db: Session = Depends(get_db),
    current_user: User = Depends(allow_all)
):
    filters = []
    
    if indicator_type:
        filters.append(IOC.indicator_type == indicator_type.upper())
    if severity:
        filters.append(IOC.severity == severity.upper())
    if status:
        filters.append(IOC.status == status.upper())
    if start_date:
        filters.append(IOC.created_at >= start_date)
    if end_date:
        filters.append(IOC.created_at <= end_date)
    if query:
        # Search exact, prefix or contains
        filters.append(IOC.search_text.contains(query.lower()))

    # If source is specified, join with ThreatFeed
    q = db.query(IOC)
    if source:
        q = q.join(ThreatFeed, IOC.source_feed_id == ThreatFeed.id).filter(
            ThreatFeed.name.ilike(source)
        )

    iocs = q.filter(and_(*filters) if filters else True).all()

    # Load metadata for each IOC to build the response
    results = []
    for ioc in iocs:
        meta = db.query(IOCMetadata).filter(IOCMetadata.ioc_id == ioc.id).first()
        res = IOCResponse(
            id=ioc.id,
            indicator_value=ioc.indicator_value,
            indicator_type=ioc.indicator_type,
            confidence_score=ioc.confidence_score,
            severity=ioc.severity,
            first_seen=ioc.first_seen,
            last_seen=ioc.last_seen,
            source_feed_id=ioc.source_feed_id,
            status=ioc.status,
            normalized_indicator=ioc.normalized_indicator,
            search_text=ioc.search_text,
            created_at=ioc.created_at,
            metadata=meta
        )
        results.append(res)

    return results

@router.get("/{ioc_id}", response_model=IOCResponse)
def get_ioc(ioc_id: int, db: Session = Depends(get_db), current_user: User = Depends(allow_all)):
    ioc = db.query(IOC).filter(IOC.id == ioc_id).first()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")
        
    meta = db.query(IOCMetadata).filter(IOCMetadata.ioc_id == ioc.id).first()
    return IOCResponse(
        id=ioc.id,
        indicator_value=ioc.indicator_value,
        indicator_type=ioc.indicator_type,
        confidence_score=ioc.confidence_score,
        severity=ioc.severity,
        first_seen=ioc.first_seen,
        last_seen=ioc.last_seen,
        source_feed_id=ioc.source_feed_id,
        status=ioc.status,
        normalized_indicator=ioc.normalized_indicator,
        search_text=ioc.search_text,
        created_at=ioc.created_at,
        metadata=meta
    )

@router.post("/upload", status_code=status.HTTP_202_ACCEPTED)
async def upload_iocs_file(
    file: UploadFile = File(...),
    feed_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(allow_analyst_admin)
):
    # Validate extension
    filename = file.filename or ""
    ext = os.path.splitext(filename)[1].lower().replace(".", "")
    if ext not in ["csv", "json"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid file type. Only CSV and JSON uploads are allowed."
        )

    # Validate size by reading file chunks or from content_length
    temp_dir = os.path.join(os.getcwd(), "temp_uploads")
    os.makedirs(temp_dir, exist_ok=True)
    temp_file_path = os.path.join(temp_dir, f"{uuid.uuid4()}.{ext}")

    size = 0
    try:
        with open(temp_file_path, "wb") as buffer:
            while True:
                chunk = await file.read(1024 * 1024)  # Read 1MB chunk
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_UPLOAD_SIZE:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail="File size exceeds the maximum limit of 50 MB."
                    )
                buffer.write(chunk)
    except HTTPException:
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)
        raise
    except Exception as e:
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)
        raise HTTPException(status_code=500, detail=f"File save error: {str(e)}")

    # Trigger Celery Task
    task = bulk_upload_iocs.delay(temp_file_path, feed_id)

    log_audit(db, current_user.id, "UPLOAD", "IOC_FILE", task.id)

    return {"job_id": task.id, "status": "PENDING"}


@router.get("/{ioc_id}/enrichment")
def get_ioc_enrichment(ioc_id: int, db: Session = Depends(get_db), current_user: User = Depends(allow_all)):
    from src.models.enrichment import IOCEnrichment
    enrich = db.query(IOCEnrichment).filter(IOCEnrichment.ioc_id == ioc_id).first()
    if not enrich:
        raise HTTPException(status_code=404, detail="Enrichment not found for this IOC")
    return enrich


@router.post("/{ioc_id}/enrich")
def enrich_ioc_endpoint(ioc_id: int, db: Session = Depends(get_db), current_user: User = Depends(allow_analyst_admin)):
    from src.services.enrichment_engine import EnrichmentEngine
    engine = EnrichmentEngine(db)
    try:
        enrichment = engine.enrich_ioc(ioc_id)
        # Recalculate Risk & Severity
        from src.services.severity_engine import SeverityEngine
        from src.services.risk_engine import RiskEngine
        
        sev = SeverityEngine(db).calculate_severity(ioc_id)
        ioc = db.query(IOC).filter(IOC.id == ioc_id).first()
        if ioc:
            ioc.severity = sev
            db.commit()
            
        RiskEngine(db).calculate_risk(ioc_id)
        db.refresh(enrichment)
        return enrichment
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/{ioc_id}/timeline")
def get_ioc_timeline(ioc_id: int, db: Session = Depends(get_db), current_user: User = Depends(allow_all)):
    from src.models.timeline import IntelligenceTimelineEvent
    events = db.query(IntelligenceTimelineEvent).filter(
        IntelligenceTimelineEvent.ioc_id == ioc_id
    ).order_by(IntelligenceTimelineEvent.event_timestamp.asc()).all()
    return events


@router.get("/{ioc_id}/blast-radius")
def get_ioc_blast_radius(ioc_id: int, db: Session = Depends(get_db), current_user: User = Depends(allow_all)):
    from src.services.blast_radius_engine import BlastRadiusEngine
    engine = BlastRadiusEngine(db)
    try:
        snap = engine.calculate_blast_radius(ioc_id)
        return snap
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

