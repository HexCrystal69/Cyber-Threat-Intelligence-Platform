import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from src.database import Base

class AlertCorrelationRun(Base):
    __tablename__ = "alert_correlation_runs"

    id = Column(String, primary_key=True, index=True)  # UUID
    status = Column(String, nullable=False)  # RUNNING, SUCCESS, FAILED
    alerts_processed = Column(Integer, default=0, nullable=False)
    groups_created = Column(Integer, default=0, nullable=False)
    started_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)


class AlertGroup(Base):
    __tablename__ = "alert_groups"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    severity = Column(String, default="MEDIUM", nullable=False)
    alert_count = Column(Integer, default=1, nullable=False)
    confidence_score = Column(Integer, default=50, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)


class AlertGroupMember(Base):
    __tablename__ = "alert_group_members"

    id = Column(Integer, primary_key=True, index=True)
    alert_group_id = Column(Integer, ForeignKey("alert_groups.id", ondelete="CASCADE"), nullable=False)
    alert_id = Column(Integer, ForeignKey("security_alerts.id", ondelete="CASCADE"), nullable=False)
