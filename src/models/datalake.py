import datetime
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, Float
from src.database import Base

class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)
    event_source = Column(String, nullable=False, index=True)  # SIEM, EDR, Firewall, etc.
    event_type = Column(String, nullable=False, index=True)
    severity = Column(String, default="INFO", nullable=False)
    normalized_json = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

class SecurityEventPartition(Base):
    __tablename__ = "security_event_partitions"

    id = Column(Integer, primary_key=True, index=True)
    partition_date = Column(String, nullable=False, unique=True, index=True)  # e.g., YYYY-MM-DD
    event_count = Column(Integer, default=0, nullable=False)
    storage_size_mb = Column(Float, default=0.0, nullable=False)

class DataLakeRetentionPolicy(Base):
    __tablename__ = "datalake_retention_policies"

    id = Column(Integer, primary_key=True, index=True)
    retention_days = Column(Integer, default=90, nullable=False)
    archive_enabled = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
