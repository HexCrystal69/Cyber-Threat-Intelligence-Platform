import datetime
from sqlalchemy import Column, Integer, String, DateTime, JSON
from src.database import Base

class DeadLetterEvent(Base):
    __tablename__ = "dead_letter_events"

    id = Column(Integer, primary_key=True, index=True)
    topic = Column(String, nullable=False)
    payload_json = Column(JSON, nullable=False)
    error_message = Column(String, nullable=False)
    retry_count = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
