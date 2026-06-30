import logging
from celery import shared_task
from prometheus_client import Counter
from src.celery_app import celery_app
from src.database import SessionLocal
from src.services.case_engine import CaseEngine
from src.services.playbook_engine import PlaybookEngine

logger = logging.getLogger(__name__)

# Prometheus metrics
cases_created_total = Counter("cases_created_total", "Total investigation cases opened")
playbooks_executed_total = Counter("playbooks_executed_total", "Total playbooks triggered")

@celery_app.task
def create_case_from_alert(alert_id: int, user_id: int = 1):
    db = SessionLocal()
    try:
        from src.models.alert import SecurityAlert
        alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
        if not alert:
            db.close()
            return {"status": "FAILED", "reason": "alert_not_found"}

        engine = CaseEngine(db)
        case = engine.create_case(
            title=f"Escalated Case: {alert.title}",
            description=f"Auto-escalated from Security Alert #{alert_id}.",
            severity=alert.severity,
            user_id=user_id
        )
        engine.attach_alert_to_case(case.id, alert_id, user_id)
        
        # Attach IOC as evidence
        from src.models.alert import AlertEvidence
        evidence = db.query(AlertEvidence).filter(
            AlertEvidence.alert_id == alert_id,
            AlertEvidence.evidence_type == "IOC"
        ).first()
        if evidence:
            engine.attach_evidence_to_case(case.id, "IOC", evidence.evidence_id)

        cases_created_total.inc()
        db.close()
        return {"status": "SUCCESS", "case_id": case.id}
    except Exception as e:
        logger.error(f"Failed to create case from alert: {e}")
        db.close()
        raise

@celery_app.task
def close_case(case_id: int, user_id: int = 1):
    db = SessionLocal()
    try:
        engine = CaseEngine(db)
        engine.update_case_status(case_id, "CLOSED", user_id)
        db.close()
        return {"status": "SUCCESS"}
    except Exception as e:
        logger.error(f"Failed to close case: {e}")
        db.close()
        raise

@celery_app.task
def execute_playbook_task(playbook_id: int, target_ioc_id: int, user_id: int = 1):
    db = SessionLocal()
    try:
        engine = PlaybookEngine(db)
        success = engine.execute_playbook(playbook_id, target_ioc_id, user_id)
        if success:
            playbooks_executed_total.inc()
        db.close()
        return {"status": "SUCCESS", "executed": success}
    except Exception as e:
        logger.error(f"Playbook execution failed: {e}")
        db.close()
        raise
