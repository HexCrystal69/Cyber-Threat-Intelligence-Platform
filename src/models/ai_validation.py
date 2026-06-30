import datetime
from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey
from src.database import Base

class ClaimValidation(Base):
    __tablename__ = "claim_validations"

    id = Column(Integer, primary_key=True, index=True)
    validation_run_id = Column(Integer, ForeignKey("ai_validation_runs.id"), nullable=False)
    claim_text = Column(String, nullable=False)
    supported = Column(Boolean, default=True, nullable=False)
    supporting_evidence_count = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
