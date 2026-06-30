import datetime
from sqlalchemy import Column, Integer, Float, DateTime, String
from src.database import Base

class DetectionCoverageSnapshot(Base):
    __tablename__ = "detection_coverage_snapshots"

    id = Column(Integer, primary_key=True, index=True)
    total_rules = Column(Integer, default=0, nullable=False)
    total_techniques = Column(Integer, default=0, nullable=False)
    covered_techniques = Column(Integer, default=0, nullable=False)
    coverage_pct = Column(Float, default=0.0, nullable=False)
    snapshot_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)


class CoverageMatrix(Base):
    __tablename__ = "coverage_matrices"

    id = Column(Integer, primary_key=True, index=True)
    attack_technique_id = Column(String, nullable=False, index=True)
    rule_count = Column(Integer, default=0, nullable=False)
    coverage_score = Column(Float, default=0.0, nullable=False)
    snapshot_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
