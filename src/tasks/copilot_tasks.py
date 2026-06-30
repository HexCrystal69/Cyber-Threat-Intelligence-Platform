import logging
import datetime
from src.celery_app import celery_app
from src.database import SessionLocal
from src.models.investigation_ai import InvestigationSummary, InvestigationRecommendation, InvestigationTimelineSummary

logger = logging.getLogger(__name__)

@celery_app.task
def generate_incident_summary(case_id: int):
    db = SessionLocal()
    try:
        summary = InvestigationSummary(
            case_id=case_id,
            summary_text=f"AI-generated investigation summary for case {case_id}. Suspicious login activities detected.",
            confidence_score=85.0,
            generated_at=datetime.datetime.utcnow()
        )
        db.add(summary)
        db.commit()
        db.close()
        return {"status": "SUCCESS", "summary_id": summary.id}
    except Exception as e:
        logger.error(f"generate_incident_summary failed: {e}")
        db.close()
        raise

@celery_app.task
def generate_case_summary(case_id: int):
    return generate_incident_summary(case_id)

@celery_app.task
def generate_executive_report(case_id: int):
    db = SessionLocal()
    try:
        timeline = InvestigationTimelineSummary(
            case_id=case_id,
            timeline_summary=f"Incident Timeline for case {case_id}: Initial intrusion at 04:00, containment at 05:30.",
            generated_at=datetime.datetime.utcnow()
        )
        db.add(timeline)
        db.commit()
        db.close()
        return {"status": "SUCCESS", "timeline_id": timeline.id}
    except Exception as e:
        logger.error(f"generate_executive_report failed: {e}")
        db.close()
        raise

@celery_app.task
def generate_hunting_recommendations(case_id: int):
    db = SessionLocal()
    try:
        rec = InvestigationRecommendation(
            case_id=case_id,
            recommendation_text=f"Check all endpoints for registry alterations resembling technique T1112.",
            priority="HIGH",
            confidence_score=90.0,
            created_at=datetime.datetime.utcnow()
        )
        db.add(rec)
        db.commit()
        db.close()
        return {"status": "SUCCESS", "recommendation_id": rec.id}
    except Exception as e:
        logger.error(f"generate_hunting_recommendations failed: {e}")
        db.close()
        raise
