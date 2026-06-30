import datetime
from sqlalchemy import Column, Integer, DateTime, Float
from src.database import Base

class ThreatExposureSnapshot(Base):
    __tablename__ = "threat_exposure_snapshots"

    id = Column(Integer, primary_key=True, index=True)
    critical_assets = Column(Integer, default=0, nullable=False)
    high_risk_assets = Column(Integer, default=0, nullable=False)
    active_campaigns = Column(Integer, default=0, nullable=False)
    active_actors = Column(Integer, default=0, nullable=False)
    critical_alerts = Column(Integer, default=0, nullable=False)
    exposure_score = Column(Float, default=0.0, nullable=False)
    snapshot_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
