import datetime
from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey
from src.database import Base

class MISPInstance(Base):
    __tablename__ = "misp_instances"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    url = Column(String, nullable=False)
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

class MISPSyncJob(Base):
    __tablename__ = "misp_sync_jobs"

    id = Column(Integer, primary_key=True, index=True)
    instance_id = Column(Integer, ForeignKey("misp_instances.id"), nullable=False)
    status = Column(String, nullable=False)  # RUNNING, SUCCESS, FAILED
    imported_iocs = Column(Integer, default=0)
    exported_iocs = Column(Integer, default=0)
    started_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)

class MISPEvent(Base):
    __tablename__ = "misp_events"

    id = Column(Integer, primary_key=True, index=True)
    misp_event_id = Column(String, unique=True, index=True)
    title = Column(String, nullable=False)
    threat_level = Column(String, nullable=True)
    published = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

class MISPAttribute(Base):
    __tablename__ = "misp_attributes"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(Integer, ForeignKey("misp_events.id"), nullable=False)
    attribute_type = Column(String, nullable=False)
    value = Column(String, nullable=False, index=True)
    category = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
