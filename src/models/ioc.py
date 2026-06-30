import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON
from src.database import Base

class IOC(Base):
    __tablename__ = "iocs"

    id = Column(Integer, primary_key=True, index=True)
    indicator_value = Column(String, index=True, nullable=False)
    indicator_type = Column(String, index=True, nullable=False)  # IP, DOMAIN, URL, HASH_MD5, HASH_SHA1, HASH_SHA256, EMAIL
    confidence_score = Column(Integer, default=50, nullable=False)
    severity = Column(String, default="INFO", nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL, INFO
    first_seen = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    last_seen = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    source_feed_id = Column(Integer, ForeignKey("threat_feeds.id"), nullable=True)
    status = Column(String, default="ACTIVE", nullable=False)  # ACTIVE, EXPIRED, FALSE_POSITIVE
    normalized_indicator = Column(String, index=True, nullable=False)
    search_text = Column(String, index=True, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)


class IOCMetadata(Base):
    __tablename__ = "ioc_metadata"

    id = Column(Integer, primary_key=True, index=True)
    ioc_id = Column(Integer, ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False)
    country = Column(String, nullable=True)
    asn = Column(String, nullable=True)
    organization = Column(String, nullable=True)
    tags = Column(JSON, default=list, nullable=True)
    raw_data = Column(JSON, default=dict, nullable=True)


class IOCFingerprint(Base):
    __tablename__ = "ioc_fingerprints"

    id = Column(Integer, primary_key=True, index=True)
    ioc_id = Column(Integer, ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False)
    sha256_fingerprint = Column(String, unique=True, index=True, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
