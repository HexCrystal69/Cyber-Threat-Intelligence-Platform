import datetime
import json
import logging
import time
from celery import shared_task
from prometheus_client import Counter, Histogram
from sqlalchemy.orm import Session
from src.celery_app import celery_app
from src.database import SessionLocal
from src.models.ioc import IOC
from src.models.enrichment import IOCEnrichment
from src.models.timeline import IntelligenceTimelineEvent
from src.models.campaign import ThreatCampaign, CampaignIOC, CampaignTimelineEvent
from src.models.replay import ProcessedEvent
from src.models.dlq import DeadLetterEvent
from src.services.enrichment_engine import EnrichmentEngine
from src.services.severity_engine import SeverityEngine
from src.services.risk_engine import RiskEngine
from src.services.correlation_engine import CorrelationEngine
from src.services.attribution_engine import AttributionEngine

logger = logging.getLogger(__name__)

# Prometheus metrics
stream_events_processed_total = Counter(
    "stream_events_processed_total",
    "Total stream events processed successfully",
    ["topic"]
)
stream_events_failed_total = Counter(
    "stream_events_failed_total",
    "Total stream events failed",
    ["topic"]
)
stream_retry_total = Counter(
    "stream_retry_total",
    "Total stream event retries",
    ["topic"]
)
dead_letter_events_total = Counter(
    "dead_letter_events_total",
    "Total events routed to dead letter queue",
    ["topic"]
)
correlation_runtime_seconds = Histogram(
    "correlation_runtime_seconds",
    "Time spent running correlation engine in seconds"
)


def is_already_processed(db: Session, event_id: str, topic: str, partition: int, offset: int) -> bool:
    if event_id:
        existing = db.query(ProcessedEvent).filter(ProcessedEvent.event_id == event_id).first()
        if existing:
            return True
    # Fallback to partition/offset
    existing_offset = db.query(ProcessedEvent).filter(
        ProcessedEvent.topic == topic,
        ProcessedEvent.partition == partition,
        ProcessedEvent.offset == offset
    ).first()
    return existing_offset is not None


def mark_as_processed(db: Session, event_id: str, topic: str, partition: int, offset: int):
    pe = ProcessedEvent(
        event_id=event_id or f"evt_{topic}_{partition}_{offset}",
        topic=topic,
        partition=partition,
        offset=offset,
        processed_at=datetime.datetime.utcnow()
    )
    db.add(pe)
    db.commit()


def route_to_dlq(db: Session, topic: str, payload: dict, error_msg: str, retry_count: int = 0):
    dlq_event = DeadLetterEvent(
        topic=topic,
        payload_json=payload,
        error_message=error_msg,
        retry_count=retry_count
    )
    db.add(dlq_event)
    db.commit()
    dead_letter_events_total.labels(topic=topic).inc()


@celery_app.task(bind=True, max_retries=3)
def process_stream_event(self, topic: str, payload: dict, partition: int = 0, offset: int = 0):
    event_id = payload.get("event_id") or payload.get("ioc_id") or payload.get("job_id")
    event_id = str(event_id) if event_id else None
    
    db = SessionLocal()
    try:
        # 1. Replay Protection check
        if is_already_processed(db, event_id, topic, partition, offset):
            logger.info(f"Skipping already processed event: {event_id} from {topic}")
            db.close()
            return {"status": "SKIPPED", "reason": "replay_protection"}

        # 2. Topic Event Routing
        if topic == "threat-feed-events":
            # Triggers enrichment
            ioc_id = payload.get("ioc_id")
            if ioc_id:
                engine = EnrichmentEngine(db)
                engine.enrich_ioc(ioc_id)

        elif topic == "ioc-created":
            # Triggers: Enrichment, Correlation, Timeline Event
            ioc_id = payload.get("ioc_id")
            if ioc_id:
                # Enrichment
                enrich_engine = EnrichmentEngine(db)
                enrich_engine.enrich_ioc(ioc_id)
                
                # Severity and Risk engine updates
                sev_engine = SeverityEngine(db)
                sev = sev_engine.calculate_severity(ioc_id)
                
                ioc = db.query(IOC).filter(IOC.id == ioc_id).first()
                if ioc:
                    ioc.severity = sev
                    db.commit()
                
                risk_engine = RiskEngine(db)
                risk_engine.calculate_risk(ioc_id)

                # Timeline Event
                timeline_evt = IntelligenceTimelineEvent(
                    ioc_id=ioc_id,
                    event_type="ENRICHED",
                    event_description=f"IOC created and enriched successfully with severity {sev}.",
                    event_source="IOC"
                )
                db.add(timeline_evt)
                db.commit()

                # Trigger Correlation Run
                corr_engine = CorrelationEngine(db)
                corr_engine.run_correlation()

        elif topic == "ioc-updated":
            # Triggers: Reputation Recalculation
            ioc_id = payload.get("ioc_id")
            if ioc_id:
                ioc = db.query(IOC).filter(IOC.id == ioc_id).first()
                if ioc:
                    enrich_engine = EnrichmentEngine(db)
                    enrich_engine.enrich_ioc(ioc_id)

                    timeline_evt = IntelligenceTimelineEvent(
                        ioc_id=ioc_id,
                        event_type="RISK_CHANGED",
                        event_description="IOC details updated, reputation recalculated.",
                        event_source="Correlation"
                    )
                    db.add(timeline_evt)
                    db.commit()

        elif topic == "correlation-events":
            # Triggers: Campaign Updates
            campaign_id = payload.get("campaign_id")
            if campaign_id:
                attribution = AttributionEngine(db)
                attribution.attribute_campaign(campaign_id)

                camp_timeline = CampaignTimelineEvent(
                    campaign_id=campaign_id,
                    event_type="EXPANDED",
                    description="Campaign elements updated via stream correlation trigger."
                )
                db.add(camp_timeline)
                db.commit()

        # Mark as processed
        mark_as_processed(db, event_id, topic, partition, offset)
        stream_events_processed_total.labels(topic=topic).inc()
        db.close()
        return {"status": "SUCCESS"}

    except Exception as exc:
        logger.error(f"Failed to process event from {topic}: {exc}")
        db.rollback()
        stream_events_failed_total.labels(topic=topic).inc()
        
        # Retry logic
        retry_cnt = self.request.retries
        if retry_cnt < self.max_retries:
            stream_retry_total.labels(topic=topic).inc()
            db.close()
            raise self.retry(exc=exc, countdown=5)
        else:
            # Route to DLQ on final failure
            route_to_dlq(db, topic, payload, str(exc), retry_count=retry_cnt)
            db.close()
            return {"status": "FAILED", "reason": "moved_to_dlq", "error": str(exc)}
