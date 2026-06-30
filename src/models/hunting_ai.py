import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text, Float, ForeignKey
from src.database import Base

class NaturalLanguageQuery(Base):
    __tablename__ = "natural_language_queries"

    id = Column(Integer, primary_key=True, index=True)
    user_query = Column(String, nullable=False)
    generated_query = Column(Text, nullable=False)
    execution_status = Column(String, default="SUCCESS")
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

class QueryTranslationAudit(Base):
    __tablename__ = "query_translation_audits"

    id = Column(Integer, primary_key=True, index=True)
    nl_query_id = Column(Integer, ForeignKey("natural_language_queries.id"), nullable=False)
    confidence_score = Column(Float, default=1.0)
    validation_status = Column(String, default="PASS")  # PASS, FAIL
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
