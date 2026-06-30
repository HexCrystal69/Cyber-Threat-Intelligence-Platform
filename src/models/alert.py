import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from src.database import Base

class SecurityAlert(Base):
    __tablename__ = "security_alerts"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    severity = Column(String, default="MEDIUM", nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    priority = Column(String, default="MEDIUM", nullable=False)  # LOW, MEDIUM, HIGH, URGENT
    status = Column(String, default="NEW", nullable=False)       # NEW, OPEN, UNDER_INVESTIGATION, RESOLVED, DISMISSED
    confidence_score = Column(Integer, default=50, nullable=False)
    risk_score = Column(Integer, default=50, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)


class AlertEvidence(Base):
    __tablename__ = "alert_evidences"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(Integer, ForeignKey("security_alerts.id", ondelete="CASCADE"), nullable=False)
    evidence_type = Column(String, nullable=False)  # IOC, CAMPAIGN, ACTOR, DETECTION, HUNTING
    evidence_id = Column(String, nullable=False)
    evidence_summary = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)


class AlertComment(Base):
    __tablename__ = "alert_comments"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(Integer, ForeignKey("security_alerts.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    comment = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)


class AlertScoreHistory(Base):
    __tablename__ = "alert_score_histories"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(Integer, ForeignKey("security_alerts.id", ondelete="CASCADE"), nullable=False)
    old_score = Column(Integer, nullable=False)
    new_score = Column(Integer, nullable=False)
    reason = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
