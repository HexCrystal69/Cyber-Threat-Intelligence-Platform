import datetime
from sqlalchemy import Column, Integer, String, DateTime, Boolean
from src.database import Base

class TAXIICollection(Base):
    __tablename__ = "taxii_collections"

    id = Column(Integer, primary_key=True, index=True)
    collection_id = Column(String, unique=True, index=True)
    title = Column(String, nullable=False)
    description = Column(String, nullable=True)
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    last_sync_at = Column(DateTime, nullable=True)
    last_object_id = Column(String, nullable=True)
    sync_status = Column(String, nullable=True)  # SUCCESS, FAILED, RUNNING

class TAXIISyncJob(Base):
    __tablename__ = "taxii_sync_jobs"

    id = Column(Integer, primary_key=True, index=True)
    collection_id = Column(String, nullable=False, index=True)
    status = Column(String, nullable=False)  # RUNNING, SUCCESS, FAILED
    objects_synced = Column(Integer, default=0)
    started_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)

class TAXIICollectionState(Base):
    __tablename__ = "taxii_collection_states"

    id = Column(Integer, primary_key=True, index=True)
    collection_id = Column(String, nullable=False, index=True)
    objects_processed = Column(Integer, default=0)
    objects_added = Column(Integer, default=0)
    objects_updated = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
