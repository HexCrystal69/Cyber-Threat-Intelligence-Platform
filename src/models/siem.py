import datetime
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, ForeignKey
from src.database import Base

class SIEMConnector(Base):
    __tablename__ = "siem_connectors"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    connector_type = Column(String, nullable=False)  # SPLUNK, SENTINEL, ELASTIC, QRADAR, CHRONICLE, SYSLOG
    endpoint = Column(String, nullable=True)
    enabled = Column(Boolean, default=True)
    last_sync_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

class SIEMIngestionJob(Base):
    __tablename__ = "siem_ingestion_jobs"

    id = Column(Integer, primary_key=True, index=True)
    connector_id = Column(Integer, ForeignKey("siem_connectors.id"), nullable=False)
    status = Column(String, nullable=False)  # RUNNING, SUCCESS, FAILED
    records_ingested = Column(Integer, default=0)
    started_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)

class SIEMEvent(Base):
    __tablename__ = "siem_events"

    id = Column(Integer, primary_key=True, index=True)
    connector_id = Column(Integer, ForeignKey("siem_connectors.id"), nullable=False)
    source_event_id = Column(String, nullable=True)
    event_type = Column(String, nullable=True)
    raw_event_json = Column(Text, nullable=False)
    normalized_event_json = Column(Text, nullable=False)
    event_timestamp = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
