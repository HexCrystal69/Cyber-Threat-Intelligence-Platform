import os
import uuid
import time
import datetime
import asyncio
import logging
from celery import shared_task
from sqlalchemy.orm import Session
from src.database import SessionLocal
from src.celery_app import celery_app
from src.models.feed import ThreatFeed, FeedExecutionLog
from src.models.job import IngestionJob
from src.models.ioc import IOC, IOCMetadata, IOCFingerprint
from src.services.feed_collectors.openphish import OpenPhishCollector
from src.services.feed_collectors.abuseipdb import AbuseIPDBCollector
from src.services.feed_collectors.csv_upload import CSVUploadCollector
from src.kafka_client import kafka_producer
from src.utils.metrics import ioc_ingested_total, ioc_failed_total, ingestion_jobs_total, ingestion_duration_seconds

logger = logging.getLogger(__name__)

def get_db_session():
    return SessionLocal()

def publish_kafka_event_sync(topic: str, message: dict):
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.ensure_future(kafka_producer.publish_event(topic, message))
        else:
            loop.run_until_complete(kafka_producer.publish_event(topic, message))
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(kafka_producer.publish_event(topic, message))
        loop.close()
    except Exception as e:
        logger.error(f"Failed to publish event synchronously to {topic}: {e}")


def process_records(db: Session, records: list, feed_id: int, job_id: str, feed_name: str) -> tuple[int, int]:
    processed = 0
    failed = 0
    
    # Simple base collector to access compute_fingerprint
    from src.services.feed_collectors.base import BaseFeedCollector
    class HelperCollector(BaseFeedCollector):
        def fetch(self): pass
        def validate(self, r): return True
        def normalize(self, r): return r
    
    helper = HelperCollector(feed_name, "")

    for record in records:
        try:
            val = record.get("indicator_value")
            itype = record.get("indicator_type")
            fingerprint_hash = helper.compute_fingerprint(itype, val)
            
            # Check for existing fingerprint
            fingerprint = db.query(IOCFingerprint).filter(IOCFingerprint.sha256_fingerprint == fingerprint_hash).first()
            
            now = datetime.datetime.utcnow()
            if fingerprint:
                # Update existing IOC
                ioc = db.query(IOC).filter(IOC.id == fingerprint.ioc_id).first()
                if ioc:
                    ioc.last_seen = now
                    ioc.confidence_score = max(ioc.confidence_score, record.get("confidence_score", 50))
                    ioc.status = record.get("status", "ACTIVE")
                    db.commit()
                    
                    # Publish IOC updated event
                    publish_kafka_event_sync("ioc-updated", {
                        "ioc_id": ioc.id,
                        "indicator": ioc.indicator_value,
                        "type": ioc.indicator_type,
                        "source": feed_name,
                        "timestamp": now.isoformat(),
                        "action": "update"
                    })
                processed += 1
            else:
                # Create new IOC
                ioc = IOC(
                    indicator_value=val,
                    indicator_type=itype,
                    confidence_score=record.get("confidence_score", 50),
                    severity=record.get("severity", "INFO"),
                    first_seen=now,
                    last_seen=now,
                    source_feed_id=feed_id,
                    status=record.get("status", "ACTIVE"),
                    normalized_indicator=record.get("normalized_indicator", val.strip().lower()),
                    search_text=record.get("search_text", val.strip().lower()),
                    created_at=now
                )
                db.add(ioc)
                db.commit()
                db.refresh(ioc)
                
                # Add Metadata
                meta_data = record.get("metadata", {})
                ioc_metadata = IOCMetadata(
                    ioc_id=ioc.id,
                    country=meta_data.get("country"),
                    asn=meta_data.get("asn"),
                    organization=meta_data.get("organization"),
                    tags=meta_data.get("tags", []),
                    raw_data=meta_data.get("raw_data", {})
                )
                db.add(ioc_metadata)
                
                # Add Fingerprint
                ioc_fp = IOCFingerprint(
                    ioc_id=ioc.id,
                    sha256_fingerprint=fingerprint_hash,
                    created_at=now
                )
                db.add(ioc_fp)
                db.commit()
                
                # Publish IOC created event
                publish_kafka_event_sync("ioc-created", {
                    "ioc_id": ioc.id,
                    "indicator": ioc.indicator_value,
                    "type": ioc.indicator_type,
                    "source": feed_name,
                    "timestamp": now.isoformat(),
                    "action": "create"
                })
                processed += 1
                
                # Update metrics
                ioc_ingested_total.labels(feed_name=feed_name, indicator_type=itype).inc()
        except Exception as e:
            logger.error(f"Error processing record {record}: {e}")
            failed += 1
            db.rollback()
            ioc_failed_total.labels(feed_name=feed_name, reason=str(e)[:50]).inc()

    return processed, failed


@celery_app.task(bind=True)
def ingest_feed(self, feed_id: int):
    job_id = self.request.id or f"manual_job_{uuid.uuid4()}"
    db = get_db_session()
    
    feed = db.query(ThreatFeed).filter(ThreatFeed.id == feed_id).first()
    if not feed:
        logger.error(f"Feed ID {feed_id} not found.")
        db.close()
        return {"status": "FAILED", "error": "Feed not found"}
        
    if not feed.enabled:
        logger.info(f"Feed {feed.name} is disabled. Skipping.")
        db.close()
        return {"status": "SKIPPED", "reason": "Feed disabled"}

    # Track job
    job = IngestionJob(
        id=job_id,
        feed_id=feed_id,
        status="RUNNING",
        records_processed=0,
        records_failed=0,
        started_at=datetime.datetime.utcnow()
    )
    db.add(job)
    db.commit()

    start_time = time.time()
    
    # Initialize collector
    collector = None
    if feed.name.lower() == "openphish":
        collector = OpenPhishCollector(feed_source_url=feed.source_url)
    elif feed.name.lower() == "abuseipdb":
        collector = AbuseIPDBCollector(feed_source_url=feed.source_url)
    else:
        # Default or fallback generic collector
        collector = OpenPhishCollector(feed_source_url=feed.source_url)

    try:
        publish_kafka_event_sync("ingestion-events", {
            "job_id": job_id,
            "feed_name": feed.name,
            "status": "RUNNING",
            "timestamp": job.started_at.isoformat()
        })

        raw_records = collector.fetch()
        normalized_records = []
        records_failed = 0
        
        for raw in raw_records:
            if collector.validate(raw):
                normalized_records.append(collector.normalize(raw))
            else:
                records_failed += 1
                ioc_failed_total.labels(feed_name=feed.name, reason="validation_failed").inc()

        processed, failed = process_records(db, normalized_records, feed_id, job_id, feed.name)
        failed += records_failed

        duration = time.time() - start_time
        completed_at = datetime.datetime.utcnow()

        # Update Job
        job.status = "SUCCESS"
        job.records_processed = processed
        job.records_failed = failed
        job.completed_at = completed_at
        
        # Update Feed reliability metrics
        feed.success_count += 1
        feed.last_success_at = completed_at
        
        # Create execution log
        exec_log = FeedExecutionLog(
            feed_id=feed_id,
            job_id=job_id,
            status="SUCCESS",
            started_at=job.started_at,
            completed_at=completed_at,
            duration_seconds=duration,
            records_processed=processed,
            records_failed=failed
        )
        db.add(exec_log)
        db.commit()

        # Metrics
        ingestion_jobs_total.labels(feed_name=feed.name, status="SUCCESS").inc()
        ingestion_duration_seconds.labels(feed_name=feed.name).observe(duration)

        publish_kafka_event_sync("ingestion-events", {
            "job_id": job_id,
            "feed_name": feed.name,
            "status": "SUCCESS",
            "records_processed": processed,
            "records_failed": failed,
            "timestamp": completed_at.isoformat()
        })
        
        return {"status": "SUCCESS", "processed": processed, "failed": failed}

    except Exception as e:
        logger.error(f"Ingestion job {job_id} failed: {e}")
        db.rollback()
        completed_at = datetime.datetime.utcnow()
        duration = time.time() - start_time

        job.status = "FAILED"
        job.completed_at = completed_at
        job.error_message = str(e)
        
        feed.failure_count += 1
        feed.last_failure_at = completed_at

        exec_log = FeedExecutionLog(
            feed_id=feed_id,
            job_id=job_id,
            status="FAILED",
            started_at=job.started_at,
            completed_at=completed_at,
            duration_seconds=duration,
            records_processed=0,
            records_failed=0
        )
        db.add(exec_log)
        db.commit()

        ingestion_jobs_total.labels(feed_name=feed.name, status="FAILED").inc()

        publish_kafka_event_sync("ingestion-events", {
            "job_id": job_id,
            "feed_name": feed.name,
            "status": "FAILED",
            "error_message": str(e),
            "timestamp": completed_at.isoformat()
        })

        return {"status": "FAILED", "error": str(e)}
    finally:
        db.close()


@celery_app.task(bind=True)
def bulk_upload_iocs(self, file_path: str, feed_id: int = None):
    job_id = self.request.id or f"manual_upload_{uuid.uuid4()}"
    db = get_db_session()
    
    feed_name = "CSVUpload"
    if feed_id:
        feed = db.query(ThreatFeed).filter(ThreatFeed.id == feed_id).first()
        if feed:
            feed_name = feed.name

    job = IngestionJob(
        id=job_id,
        feed_id=feed_id,
        status="RUNNING",
        records_processed=0,
        records_failed=0,
        started_at=datetime.datetime.utcnow()
    )
    db.add(job)
    db.commit()

    start_time = time.time()
    collector = CSVUploadCollector()

    try:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File {file_path} does not exist.")

        content_type = "csv" if file_path.endswith(".csv") else "json"
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        raw_records = collector.fetch_from_content(content, content_type)
        normalized_records = []
        records_failed = 0

        for raw in raw_records:
            if collector.validate(raw):
                normalized_records.append(collector.normalize(raw))
            else:
                records_failed += 1
                ioc_failed_total.labels(feed_name=feed_name, reason="validation_failed").inc()

        processed, failed = process_records(db, normalized_records, feed_id, job_id, feed_name)
        failed += records_failed

        duration = time.time() - start_time
        completed_at = datetime.datetime.utcnow()

        job.status = "SUCCESS"
        job.records_processed = processed
        job.records_failed = failed
        job.completed_at = completed_at
        
        # If bound to a real feed, update reliability metrics
        if feed_id:
            feed = db.query(ThreatFeed).filter(ThreatFeed.id == feed_id).first()
            if feed:
                feed.success_count += 1
                feed.last_success_at = completed_at

        # Log execution
        if feed_id:
            exec_log = FeedExecutionLog(
                feed_id=feed_id,
                job_id=job_id,
                status="SUCCESS",
                started_at=job.started_at,
                completed_at=completed_at,
                duration_seconds=duration,
                records_processed=processed,
                records_failed=failed
            )
            db.add(exec_log)
            
        db.commit()

        ingestion_jobs_total.labels(feed_name=feed_name, status="SUCCESS").inc()

        publish_kafka_event_sync("ingestion-events", {
            "job_id": job_id,
            "feed_name": feed_name,
            "status": "SUCCESS",
            "records_processed": processed,
            "records_failed": failed,
            "timestamp": completed_at.isoformat()
        })

        # Remove temp file after successful ingestion
        try:
            os.remove(file_path)
        except Exception:
            pass

        return {"status": "SUCCESS", "processed": processed, "failed": failed}

    except Exception as e:
        logger.error(f"Bulk upload {job_id} failed: {e}")
        db.rollback()
        completed_at = datetime.datetime.utcnow()

        job.status = "FAILED"
        job.completed_at = completed_at
        job.error_message = str(e)
        db.commit()

        ingestion_jobs_total.labels(feed_name=feed_name, status="FAILED").inc()

        publish_kafka_event_sync("ingestion-events", {
            "job_id": job_id,
            "feed_name": feed_name,
            "status": "FAILED",
            "error_message": str(e),
            "timestamp": completed_at.isoformat()
        })

        try:
            os.remove(file_path)
        except Exception:
            pass

        return {"status": "FAILED", "error": str(e)}
    finally:
        db.close()
