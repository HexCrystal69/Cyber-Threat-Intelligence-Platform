import asyncio
import datetime
from sqlalchemy.orm import Session
from src.models.audit import AuditLog
from src.kafka_client import kafka_producer

def log_audit(db: Session, user_id: int, action: str, resource_type: str, resource_id: str):
    log_entry = AuditLog(
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id),
        created_at=datetime.datetime.utcnow()
    )
    db.add(log_entry)
    db.commit()
    db.refresh(log_entry)

    # Publish event to Kafka
    event_data = {
        "event_type": "audit",
        "audit_log_id": log_entry.id,
        "user_id": user_id,
        "action": action,
        "resource_type": resource_type,
        "resource_id": str(resource_id),
        "timestamp": log_entry.created_at.isoformat()
    }
    # Since Celery tasks run synchronously, they need to run async operations via loop
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.ensure_future(kafka_producer.publish_event("audit-events", event_data))
        else:
            loop.run_until_complete(kafka_producer.publish_event("audit-events", event_data))
    except RuntimeError:
        # Create a new event loop if none exists or in threads
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(kafka_producer.publish_event("audit-events", event_data))
        loop.close()
    except Exception:
        pass  # Graceful fallback if event loop publishing fails
