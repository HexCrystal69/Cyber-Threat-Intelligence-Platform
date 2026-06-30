import logging
from src.celery_app import celery_app
from src.database import SessionLocal
from src.services.edr_engine import EDREngine
from src.models.edr import EndpointDetection

logger = logging.getLogger(__name__)

@celery_app.task
def sync_edr_assets(connector_id: int):
    db = SessionLocal()
    try:
        engine = EDREngine(db)
        mock_asset = {
            "hostname": "workstation-99",
            "operating_system": "Windows 11",
            "ip_address": "10.0.0.99",
            "asset_criticality": "HIGH",
            "business_owner": "Alice Smith",
            "department": "Finance"
        }
        asset = engine.sync_endpoint(mock_asset)
        db.close()
        return {"status": "SUCCESS", "asset_id": asset.id}
    except Exception as e:
        logger.error(f"sync_edr_assets failed: {e}")
        db.close()
        raise

@celery_app.task
def sync_edr_detections(connector_id: int, endpoint_id: int):
    db = SessionLocal()
    try:
        det = EndpointDetection(
            endpoint_id=endpoint_id,
            detection_type="Credential Dumping",
            severity="CRITICAL",
            status="OPEN"
        )
        db.add(det)
        db.commit()
        
        engine = EDREngine(db)
        engine.calculate_risk(endpoint_id)
        
        db.close()
        return {"status": "SUCCESS", "detection_id": det.id}
    except Exception as e:
        logger.error(f"sync_edr_detections failed: {e}")
        db.close()
        raise

@celery_app.task
def calculate_asset_risk(endpoint_id: int):
    db = SessionLocal()
    try:
        engine = EDREngine(db)
        risk = engine.calculate_risk(endpoint_id)
        db.close()
        return {"status": "SUCCESS", "risk_score": risk}
    except Exception as e:
        logger.error(f"calculate_asset_risk failed: {e}")
        db.close()
        raise
