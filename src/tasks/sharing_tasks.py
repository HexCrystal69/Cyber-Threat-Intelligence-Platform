import logging
from src.celery_app import celery_app
from src.database import SessionLocal
from src.services.taxii_engine import TAXIIEngine
from src.services.misp_engine import MISPEngine
from src.services.stix_engine import STIXEngine

logger = logging.getLogger(__name__)

@celery_app.task
def sync_taxii(collection_id: str, sync_type: str = "pull", objects: list = None):
    db = SessionLocal()
    try:
        engine = TAXIIEngine(db)
        res = engine.sync_collection(collection_id, sync_type, objects)
        db.close()
        return res
    except Exception as e:
        logger.error(f"sync_taxii failed: {e}")
        db.close()
        raise

@celery_app.task
def sync_misp(instance_id: int, direction: str = "both"):
    db = SessionLocal()
    try:
        engine = MISPEngine(db)
        res = engine.sync_instance(instance_id, direction)
        db.close()
        return res
    except Exception as e:
        logger.error(f"sync_misp failed: {e}")
        db.close()
        raise

@celery_app.task
def export_stix_bundle(objects: list):
    db = SessionLocal()
    try:
        engine = STIXEngine(db)
        res = engine.generate_bundle(objects)
        db.close()
        return res
    except Exception as e:
        logger.error(f"export_stix_bundle failed: {e}")
        db.close()
        raise
