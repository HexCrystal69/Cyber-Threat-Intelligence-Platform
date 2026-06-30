import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Float
from src.database import Base

class SecurityControl(Base):
    __tablename__ = "security_controls"

    id = Column(Integer, primary_key=True, index=True)
    control_framework = Column(String, nullable=False, index=True)  # NIST_CSF, CIS_CONTROLS, ISO_27001
    control_id = Column(String, nullable=False, index=True)
    description = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

class ControlMapping(Base):
    __tablename__ = "control_mappings"

    id = Column(Integer, primary_key=True, index=True)
    control_id = Column(String, nullable=False, index=True)
    detection_rule_id = Column(Integer, nullable=True)
    attack_technique_id = Column(String, nullable=True)

class ComplianceSnapshot(Base):
    __tablename__ = "compliance_snapshots"

    id = Column(Integer, primary_key=True, index=True)
    framework = Column(String, nullable=False, index=True)
    compliance_score = Column(Float, default=0.0, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
