import datetime
from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Float
from src.database import Base

class EDRConnector(Base):
    __tablename__ = "edr_connectors"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    provider = Column(String, nullable=False)  # CROWDSTRIKE, DEFENDER, SENTINELONE, CARBONBLACK
    enabled = Column(Boolean, default=True)
    last_sync_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

class EndpointAsset(Base):
    __tablename__ = "endpoint_assets"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String, nullable=False, unique=True, index=True)
    operating_system = Column(String, nullable=True)
    ip_address = Column(String, nullable=True)
    risk_score = Column(Float, default=0.0)
    asset_criticality = Column(String, default="MEDIUM")  # LOW, MEDIUM, HIGH, CRITICAL
    business_owner = Column(String, nullable=True)
    department = Column(String, nullable=True)
    last_seen = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

class EndpointDetection(Base):
    __tablename__ = "endpoint_detections"

    id = Column(Integer, primary_key=True, index=True)
    endpoint_id = Column(Integer, ForeignKey("endpoint_assets.id"), nullable=False)
    detection_type = Column(String, nullable=False)
    severity = Column(String, nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    status = Column(String, default="OPEN")  # OPEN, RESOLVED, SUPPRESSED
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
