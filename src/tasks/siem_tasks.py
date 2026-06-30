import logging
from src.celery_app import celery_app
from src.database import SessionLocal
from src.services.siem_engine import SIEMEngine

logger = logging.getLogger(__name__)

def _run_sync(connector_id: int, mock_events: list):
    db = SessionLocal()
    try:
        engine = SIEMEngine(db)
        res = engine.ingest_events(connector_id, mock_events)
        db.close()
        return res
    except Exception as e:
        logger.error(f"SIEM Ingestion Task failed: {e}")
        db.close()
        raise

@celery_app.task
def sync_splunk(connector_id: int):
    mock_events = [
        {"id": "sp-1", "event_type": "Failed Login", "severity": "MEDIUM", "user": "admin"},
        {"id": "sp-2", "event_type": "Privileged Execution", "severity": "HIGH", "command": "sudo"}
    ]
    return _run_sync(connector_id, mock_events)

@celery_app.task
def sync_sentinel(connector_id: int):
    mock_events = [
        {"id": "sen-1", "event_type": "AzureAD Abnormal Sign-in", "severity": "HIGH"},
        {"id": "sen-2", "event_type": "KeyVault Access Denied", "severity": "MEDIUM"}
    ]
    return _run_sync(connector_id, mock_events)

@celery_app.task
def sync_elastic(connector_id: int):
    mock_events = [
        {"id": "el-1", "event_type": "Process Execution Rule match", "severity": "CRITICAL"}
    ]
    return _run_sync(connector_id, mock_events)

@celery_app.task
def sync_qradar(connector_id: int):
    mock_events = [
        {"id": "qr-1", "event_type": "Multiple Login Failures", "severity": "HIGH"}
    ]
    return _run_sync(connector_id, mock_events)

@celery_app.task
def sync_chronicle(connector_id: int):
    mock_events = [
        {"id": "ch-1", "event_type": "Domain Query Malicious Indicator", "severity": "HIGH"}
    ]
    return _run_sync(connector_id, mock_events)
