import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Float
from src.database import Base

class ThreatCampaign(Base):
    __tablename__ = "threat_campaigns"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    description = Column(String, nullable=True)
    severity = Column(String, default="INFO", nullable=False)
    confidence_score = Column(Integer, default=50, nullable=False)
    status = Column(String, default="ACTIVE", nullable=False)  # ACTIVE, MONITORING, DORMANT, ARCHIVED
    first_seen = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    last_seen = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    last_activity_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)


class CampaignIOC(Base):
    __tablename__ = "campaign_iocs"

    id = Column(Integer, primary_key=True, index=True)
    campaign_id = Column(Integer, ForeignKey("threat_campaigns.id", ondelete="CASCADE"), nullable=False)
    ioc_id = Column(Integer, ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)


class CampaignScoreBreakdown(Base):
    __tablename__ = "campaign_score_breakdowns"

    id = Column(Integer, primary_key=True, index=True)
    campaign_id = Column(Integer, ForeignKey("threat_campaigns.id", ondelete="CASCADE"), nullable=False)
    infrastructure_score = Column(Float, default=0.0, nullable=False)
    asn_score = Column(Float, default=0.0, nullable=False)
    registrar_score = Column(Float, default=0.0, nullable=False)
    tag_score = Column(Float, default=0.0, nullable=False)
    total_score = Column(Float, default=0.0, nullable=False)


class CampaignTimelineEvent(Base):
    __tablename__ = "campaign_timeline_events"

    id = Column(Integer, primary_key=True, index=True)
    campaign_id = Column(Integer, ForeignKey("threat_campaigns.id", ondelete="CASCADE"), nullable=False)
    event_type = Column(String, nullable=False)  # CREATED, EXPANDED, MERGED, SPLIT, DORMANT, ARCHIVED
    description = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
