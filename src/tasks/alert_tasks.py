import logging
import uuid
import datetime
from celery import shared_task
from prometheus_client import Counter
from src.celery_app import celery_app
from src.database import SessionLocal
from src.services.alert_engine import AlertEngine
from src.models.alert import SecurityAlert
from src.models.alert_correlation import AlertCorrelationRun, AlertGroup, AlertGroupMember

logger = logging.getLogger(__name__)

# Prometheus metrics
alerts_created_total = Counter("alerts_created_total", "Total alerts triggered")
alerts_escalated_total = Counter("alerts_escalated_total", "Total alerts escalated to high priority")

@celery_app.task
def create_alert(ioc_id: int):
    db = SessionLocal()
    try:
        engine = AlertEngine(db)
        alert = engine.trigger_alerts_for_ioc(ioc_id)
        if alert:
            alerts_created_total.inc()
        db.close()
        return {"status": "SUCCESS", "alert_id": alert.id if alert else None}
    except Exception as e:
        logger.error(f"Failed to create alert: {e}")
        db.close()
        raise

@celery_app.task
def correlate_alerts():
    db = SessionLocal()
    run_id = f"alert_corr_{uuid.uuid4()}"
    run = AlertCorrelationRun(
        id=run_id,
        status="RUNNING",
        started_at=datetime.datetime.utcnow()
    )
    db.add(run)
    db.commit()

    try:
        new_alerts = db.query(SecurityAlert).filter(SecurityAlert.status == "NEW").all()
        
        # Group alerts by Title prefix similarity (simple rule: same target IOC representation)
        groups = {}
        for a in new_alerts:
            # Title format: "Threat Detection Alert: IOC {val}"
            parts = a.title.split("IOC ")
            ioc_val = parts[1] if len(parts) > 1 else "Generic"
            groups.setdefault(ioc_val, []).append(a)

        groups_created = 0
        for ioc_val, alerts in groups.items():
            if len(alerts) > 1:
                # Create AlertGroup
                group = AlertGroup(
                    title=f"Correlated Alert Group - IOC: {ioc_val}",
                    severity=alerts[0].severity,
                    alert_count=len(alerts),
                    confidence_score=max(a.confidence_score for a in alerts)
                )
                db.add(group)
                db.commit()
                db.refresh(group)
                groups_created += 1

                for a in alerts:
                    member = AlertGroupMember(alert_group_id=group.id, alert_id=a.id)
                    db.add(member)
                    
                    # Update status
                    a.status = "OPEN"
                db.commit()

        run.status = "SUCCESS"
        run.alerts_processed = len(new_alerts)
        run.groups_created = groups_created
        run.completed_at = datetime.datetime.utcnow()
        db.commit()
        db.close()
        return {"status": "SUCCESS", "correlation_run_id": run_id}

    except Exception as e:
        logger.error(f"Alert correlation run failed: {e}")
        db.rollback()
        run.status = "FAILED"
        run.completed_at = datetime.datetime.utcnow()
        db.commit()
        db.close()
        raise

@celery_app.task
def escalate_alert(alert_id: int):
    db = SessionLocal()
    try:
        alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
        if alert:
            alert.priority = "URGENT"
            alert.severity = "CRITICAL"
            db.commit()
            alerts_escalated_total.inc()
        db.close()
        return {"status": "SUCCESS"}
    except Exception as e:
        logger.error(f"Failed to escalate alert: {e}")
        db.close()
        raise
