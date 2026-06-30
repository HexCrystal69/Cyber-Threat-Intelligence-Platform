import datetime
from sqlalchemy import Column, Integer, DateTime, ForeignKey
from src.database import Base

class DuplicateIOCGroup(Base):
    __tablename__ = "duplicate_ioc_groups"

    id = Column(Integer, primary_key=True, index=True)
    canonical_ioc_id = Column(Integer, ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False)
    duplicate_count = Column(Integer, default=1, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
