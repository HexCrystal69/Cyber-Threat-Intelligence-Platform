import logging
from src.celery_app import celery_app
from src.database import SessionLocal
from src.services.purple_team_engine import PurpleTeamEngine
from src.services.detection_analytics_engine import DetectionAnalyticsEngine

logger = logging.getLogger(__name__)

@celery_app.task
def execute_attack_simulation(technique_id: str, simulation_name: str):
    db = SessionLocal()
    try:
        engine = PurpleTeamEngine(db)
        res = engine.execute_simulation(technique_id, simulation_name)
        db.close()
        return res
    except Exception as e:
        logger.error(f"execute_attack_simulation failed: {e}")
        db.close()
        raise

@celery_app.task
def generate_coverage_report(techniques: list):
    db = SessionLocal()
    try:
        engine = PurpleTeamEngine(db)
        res = engine.discover_gaps(techniques)
        db.close()
        return {"status": "SUCCESS", "gaps_count": len(res)}
    except Exception as e:
        logger.error(f"generate_coverage_report failed: {e}")
        db.close()
        raise

@celery_app.task
def calculate_detection_fidelity(alert_id: int):
    db = SessionLocal()
    try:
        engine = DetectionAnalyticsEngine(db)
        score = engine.score_alert_fidelity(alert_id)
        db.close()
        return {"status": "SUCCESS", "fidelity_score": score}
    except Exception as e:
        logger.error(f"calculate_detection_fidelity failed: {e}")
        db.close()
        raise
