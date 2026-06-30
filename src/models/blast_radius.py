import datetime
from sqlalchemy import Column, Integer, DateTime, ForeignKey, JSON
from src.database import Base

class IOCBlastRadiusSnapshot(Base):
    __tablename__ = "ioc_blast_radius_snapshots"

    id = Column(Integer, primary_key=True, index=True)
    ioc_id = Column(Integer, ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False)
    impact_score = Column(Integer, default=0, nullable=False)
    snapshot_json = Column(JSON, default=dict, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
