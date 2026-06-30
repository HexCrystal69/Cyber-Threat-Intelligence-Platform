import datetime
from sqlalchemy import Column, Integer, DateTime, Float, ForeignKey
from src.database import Base

class DetectionHealthSnapshot(Base):
    __tablename__ = "detection_health_snapshots"

    id = Column(Integer, primary_key=True, index=True)
    detection_rule_id = Column(Integer, nullable=False, index=True)
    precision_score = Column(Float, default=0.0, nullable=False)
    recall_score = Column(Float, default=0.0, nullable=False)
    f1_score = Column(Float, default=0.0, nullable=False)
    false_positive_rate = Column(Float, default=0.0, nullable=False)
    snapshot_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
