import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from src.database import Base

class SavedSearch(Base):
    __tablename__ = "saved_searches"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False, unique=True)
    query_definition = Column(Text, nullable=False)
    owner = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

class SearchExecution(Base):
    __tablename__ = "search_executions"

    id = Column(Integer, primary_key=True, index=True)
    saved_search_id = Column(Integer, ForeignKey("saved_searches.id"), nullable=False)
    status = Column(String, nullable=False)  # RUNNING, SUCCESS, FAILED
    results_count = Column(Integer, default=0)
    runtime_ms = Column(Integer, default=0)
    executed_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
