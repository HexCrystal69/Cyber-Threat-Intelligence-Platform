import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Float, Boolean
from src.database import Base

class ThreatSource(Base):
    __tablename__ = "threat_sources"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    provider = Column(String, nullable=False)
    source_type = Column(String, nullable=False)  # FEED, UPLOAD, API, etc.
    url = Column(String, nullable=True)
    enabled = Column(Boolean, default=True, nullable=False)
    trust_weight = Column(Float, default=1.0, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

class IOCSourceMapping(Base):
    __tablename__ = "ioc_source_mappings"

    id = Column(Integer, primary_key=True, index=True)
    ioc_id = Column(Integer, ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False)
    source_id = Column(Integer, ForeignKey("threat_sources.id", ondelete="CASCADE"), nullable=False)
    first_seen = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    last_seen = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
