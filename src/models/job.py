import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from src.database import Base

class IngestionJob(Base):
    __tablename__ = "ingestion_jobs"

    id = Column(String, primary_key=True, index=True)  # Uses Celery task UUID or generated UUID
    feed_id = Column(Integer, ForeignKey("threat_feeds.id"), nullable=True)
    status = Column(String, default="PENDING", nullable=False)  # PENDING, RUNNING, SUCCESS, FAILED
    records_processed = Column(Integer, default=0, nullable=False)
    records_failed = Column(Integer, default=0, nullable=False)
    started_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    error_message = Column(String, nullable=True)
