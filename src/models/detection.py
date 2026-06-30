import datetime
from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Float, JSON, Text
from src.database import Base

class DetectionRule(Base):
    __tablename__ = "detection_rules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    rule_type = Column(String, nullable=False)  # YARA, SIGMA, CUSTOM
    enabled = Column(Boolean, default=True, nullable=False)
    severity = Column(String, default="INFO", nullable=False)
    version = Column(String, default="1.0", nullable=False)
    author = Column(String, nullable=True)
    description = Column(String, nullable=True)
    status = Column(String, default="STABLE", nullable=False)
    lifecycle_status = Column(String, default="DRAFT", nullable=False)  # DRAFT, TESTING, ACTIVE, DEPRECATED, RETIRED
    last_tested_at = Column(DateTime, nullable=True)
    last_triggered_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow, nullable=False)


class DetectionRuleSnapshot(Base):
    __tablename__ = "detection_rule_snapshots"

    id = Column(Integer, primary_key=True, index=True)
    detection_rule_id = Column(Integer, ForeignKey("detection_rules.id", ondelete="CASCADE"), nullable=False)
    version = Column(String, nullable=False)
    rule_content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)


class DetectionExecution(Base):
    __tablename__ = "detection_executions"

    id = Column(String, primary_key=True, index=True)  # UUID
    detection_rule_id = Column(Integer, ForeignKey("detection_rules.id", ondelete="CASCADE"), nullable=False)
    status = Column(String, nullable=False)  # PENDING, RUNNING, SUCCESS, FAILED
    matched_records = Column(Integer, default=0, nullable=False)
    execution_runtime_ms = Column(Float, default=0.0, nullable=False)
    started_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)


class DetectionMatch(Base):
    __tablename__ = "detection_matches"

    id = Column(Integer, primary_key=True, index=True)
    execution_id = Column(String, ForeignKey("detection_executions.id", ondelete="CASCADE"), nullable=False)
    ioc_id = Column(Integer, ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False)
    match_type = Column(String, nullable=False)
    evidence_json = Column(JSON, default=dict, nullable=False)
    confidence_score = Column(Integer, default=50, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
