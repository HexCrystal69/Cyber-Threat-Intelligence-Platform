import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean
from src.database import Base

class ThreatSharingPartner(Base):
    __tablename__ = "threat_sharing_partners"

    id = Column(Integer, primary_key=True, index=True)
    organization_name = Column(String, nullable=False)
    contact_email = Column(String, nullable=False)
    trust_level = Column(Integer, default=50)
    trust_score = Column(Integer, default=50)
    reputation_score = Column(Integer, default=50)
    sharing_volume = Column(Integer, default=0)
    last_shared_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

class SharedIntelligence(Base):
    __tablename__ = "shared_intelligence"

    id = Column(Integer, primary_key=True, index=True)
    partner_id = Column(Integer, ForeignKey("threat_sharing_partners.id"), nullable=False)
    object_type = Column(String, nullable=False)
    object_id = Column(String, nullable=False)
    shared_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    classification_level = Column(String, default="TLP:CLEAR")  # TLP:CLEAR, TLP:GREEN, TLP:AMBER, TLP:RED
    expiration_date = Column(DateTime, nullable=True)

class IntelligencePackage(Base):
    __tablename__ = "intelligence_packages"

    id = Column(Integer, primary_key=True, index=True)
    package_name = Column(String, nullable=False)
    package_type = Column(String, nullable=False)  # STIX, TAXII, MISP, CUSTOM
    object_count = Column(Integer, default=0)
    checksum = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

class SharingAudit(Base):
    __tablename__ = "sharing_audits"

    id = Column(Integer, primary_key=True, index=True)
    partner_id = Column(Integer, ForeignKey("threat_sharing_partners.id"), nullable=False)
    action_type = Column(String, nullable=False)  # SHARED, IMPORTED, REJECTED
    object_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

class PartnerConfig(Base):
    __tablename__ = "partner_configs"

    id = Column(Integer, primary_key=True, index=True)
    partner_id = Column(Integer, ForeignKey("threat_sharing_partners.id"), nullable=False)
    api_key = Column(String, nullable=False)
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
