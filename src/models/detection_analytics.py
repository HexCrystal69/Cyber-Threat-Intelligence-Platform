import datetime
from sqlalchemy import Column, Integer, String, DateTime, Float, ForeignKey, Text
from src.database import Base

class DetectionAnalyticsSnapshot(Base):
    __tablename__ = "detection_analytics_snapshots"

    id = Column(Integer, primary_key=True, index=True)
    detection_rule_id = Column(Integer, nullable=False, index=True)
    true_positives = Column(Integer, default=0, nullable=False)
    false_positives = Column(Integer, default=0, nullable=False)
    false_negatives = Column(Integer, default=0, nullable=False)
    precision_score = Column(Float, default=0.0, nullable=False)
    recall_score = Column(Float, default=0.0, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

class AlertFidelityScore(Base):
    __tablename__ = "alert_fidelity_scores"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(Integer, nullable=False, index=True)
    fidelity_score = Column(Float, default=0.0, nullable=False)
    reasoning = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
