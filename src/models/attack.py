from sqlalchemy import Column, Integer, String, ForeignKey
from src.database import Base

class AttackTechnique(Base):
    __tablename__ = "attack_techniques"

    id = Column(Integer, primary_key=True, index=True)
    technique_id = Column(String, unique=True, index=True, nullable=False)  # Txxxx
    name = Column(String, nullable=False)
    tactic = Column(String, nullable=False)
    description = Column(String, nullable=True)


class DetectionTechnique(Base):
    __tablename__ = "detection_techniques"

    id = Column(Integer, primary_key=True, index=True)
    detection_rule_id = Column(Integer, ForeignKey("detection_rules.id", ondelete="CASCADE"), nullable=False)
    attack_technique_id = Column(Integer, ForeignKey("attack_techniques.id", ondelete="CASCADE"), nullable=False)


class CampaignTechnique(Base):
    __tablename__ = "campaign_techniques"

    id = Column(Integer, primary_key=True, index=True)
    campaign_id = Column(Integer, ForeignKey("threat_campaigns.id", ondelete="CASCADE"), nullable=False)
    attack_technique_id = Column(Integer, ForeignKey("attack_techniques.id", ondelete="CASCADE"), nullable=False)
