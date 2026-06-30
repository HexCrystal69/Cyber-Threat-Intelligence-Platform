import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text, Float, ForeignKey
from src.database import Base

class InvestigationSummary(Base):
    __tablename__ = "investigation_summaries"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, nullable=False, index=True)
    summary_text = Column(Text, nullable=False)
    confidence_score = Column(Float, default=50.0)
    generated_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

class InvestigationRecommendation(Base):
    __tablename__ = "investigation_recommendations"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, nullable=False, index=True)
    recommendation_text = Column(Text, nullable=False)
    priority = Column(String, default="MEDIUM")  # LOW, MEDIUM, HIGH, CRITICAL
    confidence_score = Column(Float, default=50.0)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

class InvestigationTimelineSummary(Base):
    __tablename__ = "investigation_timeline_summaries"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, nullable=False, index=True)
    timeline_summary = Column(Text, nullable=False)
    generated_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
