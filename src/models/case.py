import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from src.database import Base

class InvestigationCase(Base):
    __tablename__ = "investigation_cases"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String, default="MEDIUM", nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    status = Column(String, default="OPEN", nullable=False)       # OPEN, UNDER_INVESTIGATION, RESOLVED, CLOSED
    owner = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    closed_at = Column(DateTime, nullable=True)


class CaseAlert(Base):
    __tablename__ = "case_alerts"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("investigation_cases.id", ondelete="CASCADE"), nullable=False)
    alert_id = Column(Integer, ForeignKey("security_alerts.id", ondelete="CASCADE"), nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)


class CaseEvidence(Base):
    __tablename__ = "case_evidences"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("investigation_cases.id", ondelete="CASCADE"), nullable=False)
    evidence_type = Column(String, nullable=False)  # IOC, CAMPAIGN, ACTOR, DETECTION, HUNTING
    evidence_id = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
