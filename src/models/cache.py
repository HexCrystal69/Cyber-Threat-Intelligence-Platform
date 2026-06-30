import datetime
from sqlalchemy import Column, Integer, String, DateTime, JSON
from src.database import Base

class ThreatCache(Base):
    __tablename__ = "threat_cache"

    id = Column(Integer, primary_key=True, index=True)
    cache_key = Column(String, unique=True, index=True, nullable=False)
    provider = Column(String, nullable=False)
    response_json = Column(JSON, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
