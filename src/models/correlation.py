import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Float, JSON
from src.database import Base

class CorrelationGroup(Base):
    __tablename__ = "correlation_groups"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    severity = Column(String, default="INFO", nullable=False)
    confidence_score = Column(Integer, default=50, nullable=False)
    ioc_count = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)


class CorrelationEvidence(Base):
    __tablename__ = "correlation_evidences"

    id = Column(Integer, primary_key=True, index=True)
    correlation_group_id = Column(Integer, ForeignKey("correlation_groups.id", ondelete="CASCADE"), nullable=False)
    ioc_id = Column(Integer, ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False)
    evidence_type = Column(String, nullable=False)  # IP, ASN, REGISTRAR, SIMILARITY, etc.
    evidence_value = Column(String, nullable=False)
    confidence = Column(Integer, default=50, nullable=False)
    weight = Column(Float, default=1.0, nullable=False)
    score_contribution = Column(Float, default=0.0, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)


class CorrelationRun(Base):
    __tablename__ = "correlation_runs"

    id = Column(String, primary_key=True, index=True)
    status = Column(String, default="PENDING", nullable=False)  # PENDING, RUNNING, SUCCESS, FAILED
    total_iocs = Column(Integer, default=0, nullable=False)
    groups_created = Column(Integer, default=0, nullable=False)
    relationships_created = Column(Integer, default=0, nullable=False)
    started_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    error_message = Column(String, nullable=True)


class CorrelationSnapshot(Base):
    __tablename__ = "correlation_snapshots"

    id = Column(Integer, primary_key=True, index=True)
    correlation_run_id = Column(String, ForeignKey("correlation_runs.id", ondelete="CASCADE"), nullable=False)
    group_count = Column(Integer, default=0, nullable=False)
    relationship_count = Column(Integer, default=0, nullable=False)
    snapshot_json = Column(JSON, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
