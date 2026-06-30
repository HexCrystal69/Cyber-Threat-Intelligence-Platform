import datetime
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, ForeignKey
from src.database import Base

class EventSchema(Base):
    __tablename__ = "event_schemas"

    id = Column(Integer, primary_key=True, index=True)
    schema_name = Column(String, nullable=False, index=True)
    version = Column(String, nullable=False)
    schema_json = Column(Text, nullable=False)
    active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

class SchemaValidationRun(Base):
    __tablename__ = "schema_validation_runs"

    id = Column(Integer, primary_key=True, index=True)
    schema_id = Column(Integer, ForeignKey("event_schemas.id"), nullable=False)
    events_checked = Column(Integer, default=0, nullable=False)
    events_failed = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
