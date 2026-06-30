import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON
from src.database import Base

class IOCEnrichment(Base):
    __tablename__ = "ioc_enrichments"

    id = Column(Integer, primary_key=True, index=True)
    ioc_id = Column(Integer, ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False)
    provider = Column(String, nullable=False)
    country = Column(String, nullable=True)
    asn = Column(String, nullable=True)
    organization = Column(String, nullable=True)
    whois_registrar = Column(String, nullable=True)
    whois_created_date = Column(DateTime, nullable=True)
    reputation_score = Column(Integer, default=0, nullable=False)
    confidence_score = Column(Integer, default=50, nullable=False)
    raw_response_json = Column(JSON, default=dict, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
