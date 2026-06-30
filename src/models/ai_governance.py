import datetime
from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Float
from src.database import Base

class ModelRegistry(Base):
    __tablename__ = "model_registries"

    id = Column(Integer, primary_key=True, index=True)
    model_name = Column(String, nullable=False, unique=True)
    model_version = Column(String, nullable=False)
    provider = Column(String, nullable=False)  # OPENAI, ANTHROPIC, COHERE, GOOGLE, etc.
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

class PromptExecution(Base):
    __tablename__ = "prompt_executions"

    id = Column(Integer, primary_key=True, index=True)
    model_id = Column(Integer, ForeignKey("model_registries.id"), nullable=True)
    prompt_template_id = Column(Integer, nullable=True)
    token_input = Column(Integer, default=0)
    token_output = Column(Integer, default=0)
    latency_ms = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

class AIValidationRun(Base):
    __tablename__ = "ai_validation_runs"

    id = Column(Integer, primary_key=True, index=True)
    response_id = Column(Integer, nullable=False, index=True)
    supported_claims = Column(Integer, default=0)
    unsupported_claims = Column(Integer, default=0)
    validation_score = Column(Float, default=1.0)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
