import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON
from src.database import Base

class ThreatActor(Base):
    __tablename__ = "threat_actors"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    alias = Column(String, nullable=True)
    country = Column(String, nullable=True)
    description = Column(String, nullable=True)
    confidence_score = Column(Integer, default=50, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)


class ActorCampaign(Base):
    __tablename__ = "actor_campaigns"

    id = Column(Integer, primary_key=True, index=True)
    actor_id = Column(Integer, ForeignKey("threat_actors.id", ondelete="CASCADE"), nullable=False)
    campaign_id = Column(Integer, ForeignKey("threat_campaigns.id", ondelete="CASCADE"), nullable=False)
    attribution_reason = Column(String, nullable=True)
    confidence = Column(Integer, default=50, nullable=False)
    evidence_json = Column(JSON, default=dict, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
