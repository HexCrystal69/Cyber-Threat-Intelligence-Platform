import datetime
import json
from sqlalchemy.orm import Session
from src.models.datalake import SecurityEvent, SecurityEventPartition, DataLakeRetentionPolicy
from src.models.search import SavedSearch, SearchExecution
from src.models.replay import TelemetryReplayJob
from src.utils.metrics import security_events_total

class SecurityDataLake:
    def __init__(self, db: Session):
        self.db = db

    def ingest_event(self, source: str, event_type: str, severity: str, raw_json: dict) -> SecurityEvent:
        event = SecurityEvent(
            event_source=source,
            event_type=event_type,
            severity=severity,
            normalized_json=json.dumps(raw_json),
            created_at=datetime.datetime.utcnow()
        )
        self.db.add(event)
        
        today_str = datetime.date.today().isoformat()
        part = self.db.query(SecurityEventPartition).filter(SecurityEventPartition.partition_date == today_str).first()
        if not part:
            part = SecurityEventPartition(
                partition_date=today_str,
                event_count=1,
                storage_size_mb=0.001
            )
            self.db.add(part)
        else:
            part.event_count += 1
            part.storage_size_mb += 0.001

        self.db.commit()
        self.db.refresh(event)
        security_events_total.inc()
        return event

    def enforce_retention(self) -> int:
        policy = self.db.query(DataLakeRetentionPolicy).first()
        if not policy:
            return 0
        
        cutoff_date = datetime.datetime.utcnow() - datetime.timedelta(days=policy.retention_days)
        deleted = self.db.query(SecurityEvent).filter(SecurityEvent.created_at < cutoff_date).delete()
        self.db.commit()
        return deleted

    def execute_saved_search(self, search_id: int) -> dict:
        saved = self.db.query(SavedSearch).filter(SavedSearch.id == search_id).first()
        if not saved:
            raise ValueError("Saved search not found")

        exec_log = SearchExecution(
            saved_search_id=search_id,
            status="RUNNING",
            executed_at=datetime.datetime.utcnow()
        )
        self.db.add(exec_log)
        self.db.commit()
        self.db.refresh(exec_log)

        query = self.db.query(SecurityEvent)
        if saved.query_definition:
            query = query.filter(SecurityEvent.event_type.contains(saved.query_definition))

        results = query.all()
        exec_log.status = "SUCCESS"
        exec_log.results_count = len(results)
        exec_log.runtime_ms = 12
        self.db.commit()

        return {"results_count": len(results), "execution_id": exec_log.id}

    def run_replay_job(self, start_time: datetime.datetime, end_time: datetime.datetime) -> TelemetryReplayJob:
        job = TelemetryReplayJob(
            start_time=start_time,
            end_time=end_time,
            status="RUNNING",
            created_at=datetime.datetime.utcnow()
        )
        self.db.add(job)
        self.db.commit()
        self.db.refresh(job)

        events = self.db.query(SecurityEvent).filter(
            SecurityEvent.created_at >= start_time,
            SecurityEvent.created_at <= end_time
        ).all()

        for ev in events:
            new_ev = SecurityEvent(
                event_source=ev.event_source,
                event_type=f"REPLAYED_{ev.event_type}",
                severity=ev.severity,
                normalized_json=ev.normalized_json,
                created_at=datetime.datetime.utcnow()
            )
            self.db.add(new_ev)

        job.status = "SUCCESS"
        job.events_replayed = len(events)
        self.db.commit()
        return job
