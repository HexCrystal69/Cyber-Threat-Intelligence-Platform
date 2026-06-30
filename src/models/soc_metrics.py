import datetime
from sqlalchemy import Column, Integer, DateTime, Float
from src.database import Base

class SocMetricsSnapshot(Base):
    __tablename__ = "soc_metrics_snapshots"

    id = Column(Integer, primary_key=True, index=True)
    open_alerts = Column(Integer, default=0, nullable=False)
    critical_alerts = Column(Integer, default=0, nullable=False)
    active_cases = Column(Integer, default=0, nullable=False)
    mtta_minutes = Column(Float, default=0.0, nullable=False)
    mttr_minutes = Column(Float, default=0.0, nullable=False)
    detection_coverage_pct = Column(Float, default=0.0, nullable=False)
    alert_fidelity_score = Column(Float, default=0.0, nullable=False)
    snapshot_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
