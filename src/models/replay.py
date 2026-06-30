import datetime
from sqlalchemy import Column, Integer, String, DateTime
from src.database import Base

class ProcessedEvent(Base):
    __tablename__ = "processed_events"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String, unique=True, index=True, nullable=False)
    topic = Column(String, nullable=False)
    partition = Column(Integer, nullable=False)
    offset = Column(Integer, nullable=False)
    processed_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)


class TelemetryReplayJob(Base):
    __tablename__ = "telemetry_replay_jobs"

    id = Column(Integer, primary_key=True, index=True)
    start_time = Column(DateTime, nullable=False)
    end_time = Column(DateTime, nullable=False)
    status = Column(String, default="PENDING")  # PENDING, RUNNING, SUCCESS, FAILED
    events_replayed = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
