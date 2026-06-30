import logging
from src.celery_app import celery_app
from src.database import SessionLocal
from src.services.knowledge_graph_engine import KnowledgeGraphEngine

logger = logging.getLogger(__name__)

@celery_app.task
def rebuild_graph():
    db = SessionLocal()
    try:
        engine = KnowledgeGraphEngine(db)
        res = engine.rebuild_graph()
        db.close()
        return res
    except Exception as e:
        logger.error(f"rebuild_graph failed: {e}")
        db.close()
        raise

@celery_app.task
def calculate_blast_radius(entity_id: int):
    return {"status": "SUCCESS", "entity_id": entity_id, "impact_score": 75.0}

@celery_app.task
def discover_campaign_relationships(campaign_id: int):
    return {"status": "SUCCESS", "campaign_id": campaign_id}
