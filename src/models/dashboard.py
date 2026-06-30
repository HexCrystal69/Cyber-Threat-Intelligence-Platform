import datetime
from sqlalchemy import Column, Integer, Float, DateTime
from src.database import Base

class SocDashboardSnapshot(Base):
    __tablename__ = "soc_dashboard_snapshots"

    id = Column(Integer, primary_key=True, index=True)
    open_alerts = Column(Integer, default=0, nullable=False)
    critical_alerts = Column(Integer, default=0, nullable=False)
    active_cases = Column(Integer, default=0, nullable=False)
    mttr_hours = Column(Float, default=0.0, nullable=False)
    mtta_minutes = Column(Float, default=0.0, nullable=False)
    detection_coverage = Column(Float, default=0.0, nullable=False)
    snapshot_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
