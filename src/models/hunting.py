import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean, JSON, Float
from src.database import Base

class HuntingCandidate(Base):
    __tablename__ = "hunting_candidates"

    id = Column(Integer, primary_key=True, index=True)
    ioc_id = Column(Integer, ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False)
    risk_score = Column(Integer, nullable=False)
    priority = Column(String, default="LOW", nullable=False)  # LOW, MEDIUM, HIGH, URGENT
    reason = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)


class HuntingQuery(Base):
    __tablename__ = "hunting_queries"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    description = Column(String, nullable=True)
    query_type = Column(String, nullable=False)  # IOC_PIVOT, CAMPAIGN_PIVOT, ACTOR_PIVOT, INFRA_PIVOT, GRAPH
    query_definition = Column(String, nullable=False)
    tags = Column(JSON, default=list, nullable=False)
    attack_technique_id = Column(String, nullable=True)  # References MITRE ATT&CK technique code (Txxxx)
    author = Column(String, nullable=True)
    version = Column(String, default="1.0", nullable=False)
    enabled = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)


class HuntingExecution(Base):
    __tablename__ = "hunting_executions"

    id = Column(String, primary_key=True, index=True)  # UUID
    hunting_query_id = Column(Integer, ForeignKey("hunting_queries.id", ondelete="CASCADE"), nullable=False)
    status = Column(String, nullable=False)  # RUNNING, SUCCESS, FAILED
    matches_found = Column(Integer, default=0, nullable=False)
    runtime_ms = Column(Float, default=0.0, nullable=False)
    started_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)


class HuntingResult(Base):
    __tablename__ = "hunting_results"

    id = Column(Integer, primary_key=True, index=True)
    execution_id = Column(String, ForeignKey("hunting_executions.id", ondelete="CASCADE"), nullable=False)
    ioc_id = Column(Integer, ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False)
    score = Column(Integer, default=50, nullable=False)
    evidence_json = Column(JSON, default=dict, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
