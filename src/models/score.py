import datetime
from sqlalchemy import Column, Integer, DateTime, ForeignKey
from src.database import Base

class ThreatScoreSnapshot(Base):
    __tablename__ = "threat_score_snapshots"

    id = Column(Integer, primary_key=True, index=True)
    ioc_id = Column(Integer, ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False)
    severity_score = Column(Integer, nullable=False)
    risk_score = Column(Integer, nullable=False)
    reputation_score = Column(Integer, nullable=False)
    confidence_score = Column(Integer, nullable=False)
    snapshot_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
