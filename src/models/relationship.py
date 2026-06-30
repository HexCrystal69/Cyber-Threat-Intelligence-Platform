import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON
from src.database import Base

class IOCRelationship(Base):
    __tablename__ = "ioc_relationships"

    id = Column(Integer, primary_key=True, index=True)
    source_ioc_id = Column(Integer, ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False)
    target_ioc_id = Column(Integer, ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False)
    relationship_type = Column(String, nullable=False)  # RESOLVES_TO, HOSTS, ASSOCIATED_WITH, SHARES_INFRASTRUCTURE, CAMPAIGN_MEMBER
    confidence_score = Column(Integer, default=50, nullable=False)
    relationship_strength = Column(String, default="MEDIUM", nullable=False)  # WEAK, MEDIUM, STRONG
    evidence_json = Column(JSON, default=dict, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
