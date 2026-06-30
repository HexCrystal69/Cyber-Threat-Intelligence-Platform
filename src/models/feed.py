import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Float, ForeignKey
from src.database import Base

class ThreatFeed(Base):
    __tablename__ = "threat_feeds"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    source_url = Column(String, nullable=False)
    provider = Column(String, nullable=False)
    feed_type = Column(String, nullable=False)  # CSV, JSON, TXT, etc.
    enabled = Column(Boolean, default=True, nullable=False)
    success_count = Column(Integer, default=0, nullable=False)
    failure_count = Column(Integer, default=0, nullable=False)
    last_success_at = Column(DateTime, nullable=True)
    last_failure_at = Column(DateTime, nullable=True)
    trust_score = Column(Float, default=1.0, nullable=False)
    accuracy_score = Column(Float, default=1.0, nullable=False)
    false_positive_rate = Column(Float, default=0.0, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)


class FeedExecutionLog(Base):
    __tablename__ = "feed_execution_logs"

    id = Column(Integer, primary_key=True, index=True)
    feed_id = Column(Integer, ForeignKey("threat_feeds.id"), nullable=False)
    job_id = Column(String, index=True, nullable=False)
    status = Column(String, nullable=False)  # SUCCESS, FAILED
    started_at = Column(DateTime, nullable=False)
    completed_at = Column(DateTime, nullable=False)
    duration_seconds = Column(Float, nullable=False)
    records_processed = Column(Integer, default=0, nullable=False)
    records_failed = Column(Integer, default=0, nullable=False)


class FeedHealthSnapshot(Base):
    __tablename__ = "feed_health_snapshots"

    id = Column(Integer, primary_key=True, index=True)
    feed_id = Column(Integer, ForeignKey("threat_feeds.id", ondelete="CASCADE"), nullable=False)
    availability_pct = Column(Float, default=100.0, nullable=False)
    avg_runtime_ms = Column(Float, default=0.0, nullable=False)
    failure_rate = Column(Float, default=0.0, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
