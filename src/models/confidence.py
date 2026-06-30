import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from src.database import Base

class IOCConfidenceHistory(Base):
    __tablename__ = "ioc_confidence_history"

    id = Column(Integer, primary_key=True, index=True)
    ioc_id = Column(Integer, ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False)
    old_confidence = Column(Integer, nullable=False)
    new_confidence = Column(Integer, nullable=False)
    reason = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
