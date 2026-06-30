import logging
import datetime
from src.celery_app import celery_app
from src.database import SessionLocal
from src.services.response_engine import ResponseEngine
from src.models.alert import SecurityAlert
from src.models.case import InvestigationCase
from src.models.hunting import HuntingCandidate
from src.models.ioc import IOC

logger = logging.getLogger(__name__)

@celery_app.task
def execute_response(response_id: int, target_type: str, target_id: str, approver_name: str = None):
    db = SessionLocal()
    try:
        engine = ResponseEngine(db)
        res = engine.execute_response(response_id, target_type, target_id, approver_name)
        db.close()
        return res
    except Exception as e:
        logger.error(f"execute_response failed: {e}")
        db.close()
        raise

@celery_app.task
def auto_escalate_alert(alert_id: int):
    db = SessionLocal()
    try:
        alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
        if alert:
            alert.priority = "URGENT"
            alert.severity = "CRITICAL"
            db.commit()
            db.close()
            return {"status": "SUCCESS", "alert_id": alert_id}
        db.close()
        return {"status": "FAILED", "reason": "Alert not found"}
    except Exception as e:
        logger.error(f"auto_escalate_alert failed: {e}")
        db.close()
        raise

@celery_app.task
def auto_create_case(alert_id: int):
    db = SessionLocal()
    try:
        alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
        if alert:
            case = InvestigationCase(
                title=f"Auto-escalated Case for Alert: {alert.title}",
                description=f"Automated case creation for alert {alert.id}",
                severity=alert.severity,
                status="OPEN",
                created_at=datetime.datetime.utcnow()
            )
            db.add(case)
            db.commit()
            db.refresh(case)
            db.close()
            return {"status": "SUCCESS", "case_id": case.id}
        db.close()
        return {"status": "FAILED", "reason": "Alert not found"}
    except Exception as e:
        logger.error(f"auto_create_case failed: {e}")
        db.close()
        raise

@celery_app.task
def auto_hunt_ioc(ioc_id: int):
    db = SessionLocal()
    try:
        ioc = db.query(IOC).filter(IOC.id == ioc_id).first()
        if ioc:
            candidate = HuntingCandidate(
                ioc_id=ioc_id,
                risk_score=ioc.confidence_score,
                priority=ioc.severity,
                reason="Automated hunting for newly ingested IOC",
                created_at=datetime.datetime.utcnow()
            )
            db.add(candidate)
            db.commit()
            db.close()
            return {"status": "SUCCESS", "candidate_id": candidate.id}
        db.close()
        return {"status": "FAILED", "reason": "IOC not found"}
    except Exception as e:
        logger.error(f"auto_hunt_ioc failed: {e}")
        db.close()
        raise
