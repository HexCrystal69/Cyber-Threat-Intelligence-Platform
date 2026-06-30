import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from src.database import Base

class IntelligenceTimelineEvent(Base):
    __tablename__ = "intelligence_timeline_events"

    id = Column(Integer, primary_key=True, index=True)
    ioc_id = Column(Integer, ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False)
    event_type = Column(String, nullable=False)  # ENRICHED, CORRELATED, CAMPAIGN_CREATED, ACTOR_ATTRIBUTED, SEVERITY_CHANGED, RISK_CHANGED, etc.
    event_description = Column(String, nullable=False)
    event_source = Column(String, nullable=False)  # IOC, Campaign, Actor, Correlation
    event_timestamp = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
