import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text, Float, ForeignKey
from src.database import Base

class DetectionSuggestion(Base):
    __tablename__ = "detection_suggestions"

    id = Column(Integer, primary_key=True, index=True)
    technique_id = Column(String, nullable=False, index=True)
    rule_type = Column(String, nullable=False)  # YARA, SIGMA, CUSTOM
    suggested_rule = Column(Text, nullable=False)
    confidence_score = Column(Float, default=50.0)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

class DetectionReview(Base):
    __tablename__ = "detection_reviews"

    id = Column(Integer, primary_key=True, index=True)
    suggestion_id = Column(Integer, ForeignKey("detection_suggestions.id"), nullable=False)
    review_status = Column(String, default="PENDING")  # PENDING, APPROVED, REJECTED
    reviewer = Column(String, nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
