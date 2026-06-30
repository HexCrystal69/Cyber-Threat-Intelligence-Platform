import json
import datetime
from sqlalchemy.orm import Session
from src.models.siem import SIEMConnector, SIEMIngestionJob, SIEMEvent
from src.models.datalake import SecurityEvent
from src.utils.metrics import siem_events_ingested_total

class SIEMEngine:
    def __init__(self, db: Session):
        self.db = db

    def ingest_events(self, connector_id: int, raw_events: list) -> dict:
        conn = self.db.query(SIEMConnector).filter(SIEMConnector.id == connector_id).first()
        if not conn or not conn.enabled:
            raise ValueError("Connector not found or disabled")

        job = SIEMIngestionJob(
            connector_id=connector_id,
            status="RUNNING",
            started_at=datetime.datetime.utcnow()
        )
        self.db.add(job)
        self.db.commit()
        self.db.refresh(job)

        try:
            records_count = 0
            for raw_ev in raw_events:
                normalized = {
                    "event_source": conn.connector_type,
                    "event_type": raw_ev.get("event_type", "Generic"),
                    "severity": raw_ev.get("severity", "INFO"),
                    "original_id": str(raw_ev.get("id", "")),
                    "timestamp": raw_ev.get("timestamp", datetime.datetime.utcnow().isoformat())
                }

                siem_ev = SIEMEvent(
                    connector_id=connector_id,
                    source_event_id=str(raw_ev.get("id", "")),
                    event_type=raw_ev.get("event_type"),
                    raw_event_json=json.dumps(raw_ev),
                    normalized_event_json=json.dumps(normalized),
                    event_timestamp=datetime.datetime.utcnow()
                )
                self.db.add(siem_ev)

                sec_ev = SecurityEvent(
                    event_source=conn.connector_type,
                    event_type=raw_ev.get("event_type", "Generic"),
                    severity=raw_ev.get("severity", "INFO"),
                    normalized_json=json.dumps(normalized),
                    created_at=datetime.datetime.utcnow()
                )
                self.db.add(sec_ev)
                records_count += 1

            conn.last_sync_at = datetime.datetime.utcnow()
            job.status = "SUCCESS"
            job.records_ingested = records_count
            job.completed_at = datetime.datetime.utcnow()
            self.db.commit()

            siem_events_ingested_total.labels(connector_type=conn.connector_type).inc(records_count)
            return {"job_id": job.id, "records_ingested": records_count, "status": "SUCCESS"}
        except Exception as e:
            job.status = "FAILED"
            job.completed_at = datetime.datetime.utcnow()
            self.db.commit()
            raise e
