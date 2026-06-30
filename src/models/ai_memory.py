import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text
from src.database import Base

class AnalystMemory(Base):
    __tablename__ = "analyst_memories"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False, index=True)
    memory_type = Column(String, nullable=False)  # hunting_style, common_investigation, preference
    memory_key = Column(String, nullable=False, index=True)
    memory_value = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow, nullable=False)

class CopilotPreference(Base):
    __tablename__ = "copilot_preferences"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False, unique=True, index=True)
    preferred_output_style = Column(String, default="SUMMARY")  # SUMMARY, DETAILED, CRITICAL
    preferred_framework = Column(String, default="MITRE_ATTACK")
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
