from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from src.database import get_db
from src.security.auth import RoleChecker
from src.models.siem import SIEMConnector, SIEMIngestionJob

router = APIRouter(prefix="/siem", tags=["SIEM Management"])
allow_all = RoleChecker(["ADMIN", "ANALYST", "VIEWER"])
allow_analyst_admin = RoleChecker(["ADMIN", "ANALYST"])

@router.get("/connectors", status_code=status.HTTP_200_OK)
def list_connectors(db: Session = Depends(get_db), current_user = Depends(allow_all)):
    return db.query(SIEMConnector).all()

@router.post("/connectors", status_code=status.HTTP_201_CREATED)
def create_connector(name: str, connector_type: str, endpoint: str = None, db: Session = Depends(get_db), current_user = Depends(allow_analyst_admin)):
    conn = SIEMConnector(name=name, connector_type=connector_type.upper(), endpoint=endpoint, enabled=True)
    db.add(conn)
    db.commit()
    db.refresh(conn)
    return conn

@router.post("/sync", status_code=status.HTTP_202_ACCEPTED)
def sync_siem(connector_id: int, db: Session = Depends(get_db), current_user = Depends(allow_analyst_admin)):
    conn = db.query(SIEMConnector).filter(SIEMConnector.id == connector_id).first()
    if not conn:
        raise HTTPException(status_code=404, detail="Connector not found")
        
    from src.tasks.siem_tasks import sync_splunk, sync_sentinel, sync_elastic, sync_qradar, sync_chronicle
    task_map = {
        "SPLUNK": sync_splunk,
        "SENTINEL": sync_sentinel,
        "ELASTIC": sync_elastic,
        "QRADAR": sync_qradar,
        "CHRONICLE": sync_chronicle
    }
    task_func = task_map.get(conn.connector_type, sync_splunk)
    task = task_func.delay(connector_id)
    return {"task_id": task.id, "status": "PENDING"}

@router.get("/jobs", status_code=status.HTTP_200_OK)
def list_jobs(db: Session = Depends(get_db), current_user = Depends(allow_all)):
    return db.query(SIEMIngestionJob).all()
