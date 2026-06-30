import datetime
import json
from sqlalchemy.orm import Session
from src.models.schema_registry import EventSchema, SchemaValidationRun

class SchemaRegistryEngine:
    def __init__(self, db: Session):
        self.db = db

    def register_schema(self, name: str, version: str, schema_json: str) -> EventSchema:
        schema = EventSchema(
            schema_name=name,
            version=version,
            schema_json=schema_json,
            active=True,
            created_at=datetime.datetime.utcnow()
        )
        self.db.add(schema)
        self.db.commit()
        self.db.refresh(schema)
        return schema

    def validate_events(self, schema_id: int, events: list) -> dict:
        schema = self.db.query(EventSchema).filter(EventSchema.id == schema_id).first()
        if not schema or not schema.active:
            raise ValueError("Schema not found or inactive")

        try:
            schema_def = json.loads(schema.schema_json)
        except Exception:
            schema_def = {}

        failed = 0
        checked = 0
        for ev in events:
            checked += 1
            if isinstance(ev, dict):
                for k in schema_def.keys():
                    if k not in ev:
                        failed += 1
                        break
            else:
                failed += 1

        run = SchemaValidationRun(
            schema_id=schema_id,
            events_checked=checked,
            events_failed=failed,
            created_at=datetime.datetime.utcnow()
        )
        self.db.add(run)
        self.db.commit()
        self.db.refresh(run)

        return {"run_id": run.id, "checked": checked, "failed": failed}
