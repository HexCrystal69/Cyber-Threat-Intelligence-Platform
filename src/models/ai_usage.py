import datetime
from sqlalchemy import Column, Integer, String, DateTime, Float
from src.database import Base

class AIUsageSnapshot(Base):
    __tablename__ = "ai_usage_snapshots"

    id = Column(Integer, primary_key=True, index=True)
    model_name = Column(String, nullable=False, index=True)
    tokens_in = Column(Integer, default=0, nullable=False)
    tokens_out = Column(Integer, default=0, nullable=False)
    estimated_cost = Column(Float, default=0.0, nullable=False)
    request_count = Column(Integer, default=0, nullable=False)
    snapshot_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

class UserAIUsage(Base):
    __tablename__ = "user_ai_usage"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False, index=True)
    tokens_used = Column(Integer, default=0, nullable=False)
    estimated_cost = Column(Float, default=0.0, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
