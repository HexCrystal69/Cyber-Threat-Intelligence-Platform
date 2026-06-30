import logging
from celery import shared_task
from prometheus_client import Counter
from src.celery_app import celery_app
from src.database import SessionLocal
from src.services.detection_engine import DetectionEngine
from src.services.hunting_engine import HuntingEngine

logger = logging.getLogger(__name__)

# Prometheus metrics
detection_rules_executed_total = Counter("detection_rules_executed_total", "Total detection rules evaluated")
detections_matched_total = Counter("detections_matched_total", "Total matches identified by detection rules")
hunting_queries_total = Counter("hunting_queries_total", "Total hunting queries executed")
hunting_matches_total = Counter("hunting_matches_total", "Total indicators uncovered via hunting pivots")

@celery_app.task
def execute_detection_rule(rule_id: int):
    # Dummy wrapper or individual executor
    execute_all_detection_rules.delay()

@celery_app.task
def execute_all_detection_rules():
    db = SessionLocal()
    try:
        engine = DetectionEngine(db)
        exec_id = engine.execute_all_rules()
        
        # Get count
        from src.models.detection import DetectionExecution
        exe = db.query(DetectionExecution).filter(DetectionExecution.id == exec_id).first()
        if exe:
            detection_rules_executed_total.inc()
            detections_matched_total.inc(exe.matched_records)
            
        db.close()
        return {"status": "SUCCESS", "execution_id": exec_id}
    except Exception as e:
        logger.error(f"Failed to execute detection rules: {e}")
        db.close()
        raise

@celery_app.task
def execute_hunting_query(query_id: int):
    db = SessionLocal()
    try:
        engine = HuntingEngine(db)
        exec_id = engine.execute_hunt(query_id)
        
        from src.models.hunting import HuntingExecution
        exe = db.query(HuntingExecution).filter(HuntingExecution.id == exec_id).first()
        if exe:
            hunting_queries_total.inc()
            hunting_matches_total.inc(exe.matches_found)
            
        db.close()
        return {"status": "SUCCESS", "execution_id": exec_id}
    except Exception as e:
        logger.error(f"Failed to execute hunting query: {e}")
        db.close()
        raise
