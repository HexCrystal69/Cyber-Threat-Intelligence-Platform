import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from src.database import Base

class IOCSighting(Base):
    __tablename__ = "ioc_sightings"

    id = Column(Integer, primary_key=True, index=True)
    ioc_id = Column(Integer, ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False)
    source = Column(String, nullable=False)
    sighting_count = Column(Integer, default=1, nullable=False)
    first_seen = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    last_seen = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
